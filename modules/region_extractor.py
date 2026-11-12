"""Safe, evidence-driven ESP flash partition/filesystem extraction."""

import os
import shutil
import struct
import subprocess

PARTITION_TABLE_OFFSET = 0x8000
PARTITION_TABLE_MAGIC = b"\xaa\x50"
PARTITION_ENTRY_SIZE = 32
PARTITION_TABLE_MAX_ENTRIES = 95

PARTITION_TYPE_NAMES = {0x00: "app", 0x01: "data"}
PARTITION_SUBTYPE_NAMES = {
    (0x01, 0x00): "ota_data", (0x01, 0x01): "phy", (0x01, 0x02): "nvs",
    (0x01, 0x03): "coredump", (0x01, 0x04): "nvs_keys", (0x01, 0x80): "fat",
    (0x01, 0x81): "fat", (0x01, 0x82): "spiffs", (0x01, 0x83): "littlefs",
}


class RegionExtractor:
    def __init__(self, storage, logger):
        self.storage = storage
        self.logger = logger

    def extract_partition_table(self, dump_path, out_dir):
        try:
            with open(dump_path, "rb") as f:
                f.seek(PARTITION_TABLE_OFFSET)
                table = f.read(PARTITION_ENTRY_SIZE * PARTITION_TABLE_MAX_ENTRIES)
        except OSError as e:
            self.logger.warning(f"[regions] partition scan failed: {e}")
            return []

        if table[:2] != PARTITION_TABLE_MAGIC:
            self.logger.info("[regions] no IDF partition table at 0x8000")
            return []

        partitions = []
        for i in range(PARTITION_TABLE_MAX_ENTRIES):
            entry = table[i * 32:(i + 1) * 32]
            if len(entry) < 32 or entry[:2] != PARTITION_TABLE_MAGIC:
                break
            _, ptype, subtype, offset, size, name_raw, flags = struct.unpack("<2sBBII16sI", entry)
            name = name_raw.split(b"\0", 1)[0].decode("utf-8", "replace") or f"unnamed_{i}"
            partitions.append({
                "index": i, "name": name,
                "type": PARTITION_TYPE_NAMES.get(ptype, f"0x{ptype:02x}"),
                "subtype": PARTITION_SUBTYPE_NAMES.get((ptype, subtype), f"0x{subtype:02x}"),
                "ptype": ptype, "subtype_id": subtype,
                "offset": offset, "size": size, "flags": flags,
            })

        self._carve_regions(dump_path, out_dir, partitions)
        self.storage.save_analysis_result("partition_table", {"partitions": partitions})
        self.storage.log_event("partition_table", "PARSED", f"{len(partitions)} partition(s)")
        return partitions

    def _carve_regions(self, dump_path, out_dir, partitions):
        os.makedirs(out_dir, exist_ok=True)
        dump_size = os.path.getsize(dump_path)
        with open(dump_path, "rb") as src:
            for p in partitions:
                end = p["offset"] + p["size"]
                if p["offset"] < 0 or p["size"] <= 0 or end > dump_size:
                    self.logger.warning(f"[regions] skip invalid partition {p['name']}")
                    continue
                src.seek(p["offset"])
                data = src.read(p["size"])
                safe = "".join(c if c.isalnum() else "_" for c in p["name"])
                out = os.path.join(out_dir, f"partition_{p['index']:02d}_{safe}_{p['subtype']}.bin")
                try:
                    with open(out, "wb") as dst:
                        dst.write(data)
                    p["extracted_path"] = out
                except OSError as e:
                    self.logger.warning(f"[regions] cannot write {out}: {e}")

    def extract_filesystem_regions(self, dump_path, out_dir, partitions=None):
        """Prefer partition-table evidence; use heuristic carving only when requested."""
        try:
            with open(dump_path, "rb") as f:
                data = f.read()
        except OSError as e:
            self.logger.warning(f"[regions] filesystem scan failed: {e}")
            return []
        os.makedirs(out_dir, exist_ok=True)
        found = []

        # Strong evidence: filesystem subtype in a real partition table.
        for p in partitions or []:
            if p.get("subtype") in {"spiffs", "littlefs", "fat"} and p.get("extracted_path"):
                found.append({"start": p["offset"], "end": p["offset"] + p["size"], "type": p["subtype"], "confidence": 1.0, "source": "partition_table", "extracted_path": p["extracted_path"], "size": p["size"]})

        # Conservative fallback. We only carve around explicit LittleFS marker or
        # aligned SPIFFS-like pages and label them candidates, never confirmed FS.
        if not found:
            found.extend(self._find_littlefs_candidates(data))
            found.extend(self._find_spiffs_candidates(data))
            for region in found:
                out = os.path.join(out_dir, f"{region['type']}_0x{region['start']:x}.bin")
                with open(out, "wb") as dst:
                    dst.write(data[region["start"]:region["end"]])
                region["extracted_path"] = out
                region["size"] = region["end"] - region["start"]

        self.storage.save_analysis_result("filesystem_regions", {"regions": found})
        self.storage.log_event("filesystem_regions", "FOUND", f"{len(found)} region(s)")
        return found

    @staticmethod
    def _find_littlefs_candidates(data):
        candidates = []
        marker = b"littlefs"
        pos = 0
        while True:
            idx = data.find(marker, pos)
            if idx < 0:
                break
            start = max(0, idx - 0x1000)
            end = min(len(data), idx + 0x100000)
            candidates.append({"start": start, "end": end, "type": "littlefs_candidate", "confidence": 0.72, "source": "marker"})
            pos = idx + len(marker)
            if len(candidates) >= 8:
                break
        return candidates

    @staticmethod
    def _find_spiffs_candidates(data, chunk_align=0x1000):
        candidates = []
        active = None
        for offset in range(0, len(data) - chunk_align + 1, chunk_align):
            chunk = data[offset:offset + chunk_align]
            ff_ratio = chunk.count(0xFF) / len(chunk)
            non_ff = len(chunk) - chunk.count(0xFF)
            # Heuristic only: require enough real data and reject nearly empty pages.
            looks = 0.15 <= ff_ratio <= 0.97 and non_ff >= 80
            if looks and active is None:
                active = offset
            elif not looks and active is not None:
                if offset - active >= 0x4000:
                    candidates.append({"start": active, "end": offset, "type": "spiffs_candidate", "confidence": 0.45, "source": "page_heuristic"})
                active = None
            if len(candidates) >= 8:
                break
        if active is not None and len(data) - active >= 0x4000:
            candidates.append({"start": active, "end": len(data), "type": "spiffs_candidate", "confidence": 0.45, "source": "page_heuristic"})
        return candidates

    def unpack_filesystem_image(self, image_path, fs_type, out_dir, partition_size=None):
        tool = {"spiffs": "mkspiffs", "spiffs_candidate": "mkspiffs", "littlefs": "mklittlefs", "littlefs_candidate": "mklittlefs"}.get(fs_type)
        result = {"tool": tool, "available": False, "extracted_dir": None, "files": []}
        if not tool or not shutil.which(tool):
            self.logger.info(f"[regions] {tool or fs_type} unpacker not installed; raw image retained")
            return result
        unpack_dir = os.path.join(out_dir, "unpacked_" + os.path.basename(image_path))
        os.makedirs(unpack_dir, exist_ok=True)

        # mkspiffs / mklittlefs need the filesystem geometry (-s size, -b block,
        # -p page) to reliably unpack a captured image. When the region came
        # from a real partition table we know the exact size; for heuristically
        # carved candidates the size is only a guess, so the attempt is
        # clearly labelled as unverified.
        # NOTE: option order matters -- both tools declare `-u/--unpack` with
        # nargs=2, so every option must be passed BEFORE the positional
        # arguments or argparse consumes the flag as a missing argument.
        attempts = []
        if partition_size:
            attempts.append(([tool, "-s", str(partition_size), "-u", unpack_dir, image_path],
                             f"exact size {partition_size}"))
        attempts.append(([tool, "-u", unpack_dir, image_path],
                         "best effort, unverified size"))

        proc = None
        used_cmd = None
        for cmd, desc in attempts:
            self.logger.info(f"[regions] unpacking {fs_type} with {tool} ({desc})")
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            except (OSError, subprocess.TimeoutExpired) as e:
                self.logger.warning(f"[regions] {tool} failed: {e}")
                return result
            used_cmd = cmd
            if proc.returncode == 0:
                break
            self.logger.warning(
                f"[regions] {tool} rejected the image ({desc}): "
                f"{(proc.stderr or '').strip()[:300]}"
            )

        result["available"] = True
        result["command"] = " ".join(used_cmd) if used_cmd else None
        result["stdout"] = proc.stdout[-2000:] if proc else ""
        result["stderr"] = proc.stderr[-2000:] if proc else ""
        if proc.returncode != 0:
            self.logger.warning(f"[regions] {tool} could not unpack the candidate image.")
            return result
        for root, _, files in os.walk(unpack_dir):
            for name in files:
                result["files"].append(os.path.join(root, name))
        result["extracted_dir"] = unpack_dir
        return result
