# FFmpeg Miss Check Vulnerabilities Analysis

This document contains vulnerabilities found in FFmpeg git history that match the "miss check" pattern:
- Two paths share a common ancestor function
- One path has an explicit check (funC)
- Another path lacks the same check for the same object (funD), leading to vulnerability

## Criteria
1. funC has explicit check on an object
2. funD lacks check on the same object (shared ancestor context)
3. This causes crashes, memory errors, or other security issues

---

## 1. CVE-2023-6603: HLS new_init_section() Return Value Check

**Commit**: a3acba89491b0c05c4e436e2d0eda6e395917108
**File**: libavformat/hls.c
**Issue**: parse_playlist() calls new_init_section() but didn't check return value

**Pattern**:
- parse_playlist() → creates init section
- Path A: Other allocations in parse_playlist() have NULL checks
- Path B: new_init_section() return was NOT checked → NULL pointer dereference

**Fix**: Added check for cur_init_section NULL return

```c
cur_init_section = new_init_section(pls, &info, url);
+if (!cur_init_section) {
+    ret = AVERROR(ENOMEM);
+    goto fail;
+}
```

---

## 2. CVE-2023-6602: DASH Playlist SSRF Whitelist Check

**Commit**: 4c96d6bf75357ab13808efc9f08c1b41b1bf5bdf
**File**: libavformat/dashdec.c
**Issue**: Missing whitelist check for URL opening

**Pattern**:
- open_url() → opens URLs
- Path A: HLS uses ffio_open_whitelist() with whitelist check
- Path B: DASH used avio_open2() WITHOUT whitelist check → SSRF vulnerability

**Fix**: Changed to ffio_open_whitelist()

---

## 3. CVE-2022-2566: MOV build_open_gop_key_points() Integer Overflow

**Commit**: 6f53f0d09ea4c9c7f7354f018a87ef840315207d
**File**: libavformat/mov.c
**Issue**: Missing overflow check when summing counts

**Pattern**:
- build_open_gop_key_points() → sums sample offsets
- Path A: First loop added overflow check for sample_offsets_count
- Path B: Second loop (open_key_samples_count) was NOT checked → integer overflow

**Fix**: Added overflow checks for count sums

```c
+if (sc->sync_group[i].count > INT_MAX - sc->open_key_samples_count)
+    return AVERROR(ENOMEM);
```

---

## 4. libdav1d US ITU-T T.35 Heap Overflow (US vs UK Path)

**Commit**: e90c2ff4b5a5922d2cad1acd41595084f71d74a8
**File**: libavcodec/libdav1d.c
**Issue**: parse_itut_t35_metadata() missing length check for US path

**Pattern** (PERFECT EXAMPLE):
- parse_itut_t35_metadata() → handles ITU-T T.35 metadata
- Path A (UK): Already has length check before bytestream2_get_be16u()
- Path B (US): NO length check → heap overflow reading 2 bytes past allocation

**Fix**: Added check for US path similar to UK path

```c
case ITU_T_T35_COUNTRY_CODE_US:
+    if (bytestream2_get_bytes_left(&gb) < 2)
+        return AVERROR_INVALIDDATA;
    provider_code = bytestream2_get_be16u(&gb);
```

---

## 5. af_pan sscanf Return Value Check (CVE-like)

**Commit**: a43ea8bff79f23257313fc3e1a884aea9b7633ae
**File**: libavfilter/af_pan.c
**Issue**: parse_channel_name() incorrect sscanf return check

**Pattern**:
- init() → parse_channel_name()
- Path A: sscanf in init() was fixed to check >= 1 (commit b5b6391d64)
- Path B: sscanf in parse_channel_name() was still using bare truthy check → uninitialized len, OOB read

**Fix**: Changed from bare truthy check to >= 1

```c
-if (sscanf(*arg, "%7[A-Z]%n", buf, &len))
+if (sscanf(*arg, "%7[A-Z]%n", buf, &len) >= 1)
```

---

## 6. vorbisdec Rate/Order Zero Check

**Commit**: 37e99e384e37364fca13dc6a70111adb1c356fa2
**File**: libavcodec/vorbisdec.c
**Issue**: vorbis_parse_setup_hdr_floors() missing zero checks

**Pattern**:
- vorbis_parse_setup_hdr_floors() → parses floor setup
- Path A: Other parameters checked for validity
- Path B: rate and order were NOT checked for zero → division by zero later

**Fix**: Added zero checks for rate and order

```c
+if (!floor_setup->data.t0.order) {
+    av_log(vc->avccontext, AV_LOG_ERROR, "Floor 0 order is 0.\n");
+    return AVERROR_INVALIDDATA;
+}
+if (!floor_setup->data.t0.rate) {
+    av_log(vc->avccontext, AV_LOG_ERROR, "Floor 0 rate is 0.\n");
+    return AVERROR_INVALIDDATA;
+}
```

---

## 7. vorbisdec Codebook Entry Count Check

**Commit**: e6b6ae46951e242d7caf11acf5b1f10f109e1c96
**File**: libavcodec/vorbisdec.c
**Issue**: Missing check for codebook entry count

**Pattern**:
- vorbis_parse_setup_hdr_codebooks() → initializes VLC
- Path A: Other codebook parameters validated
- Path B: entries count NOT checked for <= 0 → assertion failure

**Fix**: Added check for entries <= 0

---

## 8. dnxhddec init_vlc Return Value Check (Similar to CVE-2013-0868)

**Commit**: c7b205dedd05a4983ab3ce557fdb06aa886127c9
**File**: libavcodec/dnxhddec.c
**Issue**: Missing init_vlc return value check

**Pattern**:
- dnxhd_init_vlc() → initializes VLC tables
- Path A: Other codecs check init_vlc return value
- Path B: dnxhd did NOT check init_vlc return → unspecified impact from crafted data

**Fix**: Added return value checks for all three init_vlc calls

---

## 9. vc1dec init_get_bits Return Value Checks

**Commit**: 8a1c2779a033bedb8e228e78747fde2fbe3c140c
**File**: libavcodec/vc1dec.c
**Issue**: Multiple init_get_bits calls without return checks

**Pattern**:
- vc1_decode_init() / vc1_decode_frame() → initializes bitstream context
- Path A: Some init_get_bits calls had checks
- Path B: Many init_get_bits calls were NOT checked → potential issues with huge values

**Fix**: Replaced init_get_bits with init_get_bits8 and added return checks

---

## 10. VP3 av_malloc Check

**Commit**: 5cd450dd7ae5f0b25c961fe761f8dbb4c8a7ddae
**File**: libavcodec/vp3.c
**Issue**: vp3_decode_frame() missing av_malloc check

**Pattern**:
- vp3_decode_frame() → allocates edge_emu_buffer
- Path A: Most allocations in FFmpeg have NULL checks
- Path B: edge_emu_buffer av_malloc was NOT checked → NULL pointer use

**Fix**: Added NULL check after av_malloc

---

## 11. diracdec pixel_range_index Check

**Commit**: b648b246f07a4b041dcefd7309af407c1b74862a
**File**: libavcodec/dirac.c
**Issue**: Missing pixel_range_index bounds check

**Pattern**:
- parse_source_parameters() → uses pixel_range_index to access array
- Path A: Other index parameters validated
- Path B: pixel_range_index NOT checked for < 2 → out-of-bounds read

**Fix**: Added check for pixel_range_index < 2

---

## 12. HLS Integer Overflow with EXTINF

**Commit**: f112ae503e98d9e6cf506f3a0b549aea447dc4c2
**File**: libavformat/hls.c
**Issue**: Missing overflow check for duration calculation

**Pattern**:
- parse_playlist() → parses EXTINF duration
- Path A: Other numeric values validated
- Path B: atof() result NOT checked for overflow/NaN → integer overflow

**Fix**: Added bounds check for duration

---

## 13. HTTP Connection Reuse Check

**Commit**: 4cefbc54c4ebb1d91aaecd2d548e47739e3454fc
**File**: libavformat/http.c
**Issue**: Missing s->hd NULL check before connection reuse

**Pattern**:
- http_seek_internal() → tries to reuse connection
- Path A: Other http functions check s->hd != NULL
- Path B: Connection reuse path did NOT check s->hd → crash

**Fix**: Added s->hd check before connection reuse

---

## 14. HTTP s->hd NULL Check in Read

**Commit**: 6336fa33358cd860f74c8be4772bbc303311b71e
**File**: libavformat/http.c
**Issue**: Missing s->hd NULL check in http_buf_read

**Pattern**:
- http_buf_read() → reads from HTTP connection
- Path A: Most read operations check connection validity
- Path B: http_buf_read did NOT check s->hd NULL → segfault

**Fix**: Added early return for s->hd NULL

---

## 15. LCEVC Side Data NULL Pointer Fix (libdav1d)

**Commit**: bba9bf7e7e3d14092d97a4812382cbb88b565748
**File**: libavcodec/libdav1d.c
**Issue**: Missing NULL check for side data after ff_frame_new_side_data

**Pattern**:
- libdav1d_decode_frame() → creates side data
- Path A: Most ff_frame_new_side_data callers check return
- Path B: LCEVC path did NOT check sd NULL → NULL dereference

**Fix**: Added NULL check after ff_frame_new_side_data

---

## 16. LCEVC Side Data NULL Pointer Fix (av1dec)

**Commit**: f9d289020da4153c6fb49e62073db38c9a675937
**File**: libavcodec/av1dec.c
**Issue**: Same as above - Missing NULL check for side data

**Pattern**:
- Same issue pattern as libdav1d
- Path A: Other paths check side data pointer
- Path B: LCEVC path did NOT check

---

## 17. ffv1dec NULL Pointer Offset Fix

**Commit**: 4d1a79a9ec6855b15353e8eb599036a38db142b0
**File**: libavcodec/ffv1dec.c
**Issue**: Adding offsets to NULL pointers (UB)

**Pattern**:
- decode_slice() → uses p->data[] pointers
- Path A: Some paths check for valid planes
- Path B: When chroma_planes=false, p->data[1/2] are NULL, offsets added → UB

**Fix**: Only access p->data[1/2] when chroma_planes is true

---

## 18. motion_est NULL Pointer Offset Fix

**Commit**: 99bd8a74073603482d7bf64acd54617a908ae36f
**File**: libavcodec/motion_est.c
**Issue**: Adding offsets to NULL pointers

**Pattern**:
- init_ref() → processes src/ref pointers
- Path A: Some paths handle NULL pointers
- Path B: Direct offset addition to potentially NULL pointers → UB

**Fix**: Use FF_PTR_ADD with NULL check

---

## 19. scpr3 decode_value3 Return Check

**Commit**: 938cb783d40ad5ee40f4e2be8617fdfb493dbe4d
**File**: libavcodec/scpr3.c
**Issue**: Missing return value check for decode_value3

**Pattern**:
- decompress_p3() → calls decode_value3
- Path A: Second decode_value3 call has return check
- Path B: First decode_value3 call did NOT check return → error propagation failure

**Fix**: Added return check after first decode_value3 call

---

## 20. avio_read Return Value Checks (dss/dtshd/mlv)

**Commit**: 65eed0732cadc42b3689788f175d921974f9c074
**Files**: libavformat/dss.c, dtshddec.c, mlvdec.c
**Issue**: Missing avio_read return checks

**Pattern**:
- Multiple demuxers call avio_read() without checking return
- Path A: Some avio_read calls check return value
- Path B: These specific calls did NOT check → uninitialized buffer use

**Fix**: Changed to ffio_read_size() which validates return

---

## 21. avfilter_filter_samples Bounds Check

**Commit**: ae21776207e8a2bbe268e7c9e203f7599dd87ddb
**File**: libavfilter/avfilter.c
**Issue**: Missing bounds check in loop

**Pattern**:
- avfilter_filter_samples() → copies audio data
- Path A: Similar loops in video processing have bounds checks
- Path B: Audio data loop only checked samplesref->data[i], not i < 8 → OOB access

**Fix**: Added i < 8 check in loop condition

---

## 22. avcodec_opts Existence Check

**Commit**: 819e2ab0d8d65cee0e95c89c0a4eb77aa8237c75
**File**: cmdutils.c
**Issue**: Missing NULL check for avcodec_opts array

**Pattern**:
- opt_default() → accesses avcodec_opts[]
- Path A: Some opts array accesses check existence
- Path B: Audio/Video/Subtitle specific accesses did NOT check → crash in ffprobe

**Fix**: Added NULL checks for each AVMEDIA_TYPE

---

## 23. image_get_linesize Overflow Check

**Commit**: c0170d09738c74280af78c6f64914c52a9b6e075
**File**: libavutil/imgutils.c
**Issue**: Missing overflow check in linesize calculation

**Pattern**:
- av_image_fill_linesizes() → calculates linesizes
- Path A: av_image_get_linesize() has overflow check (max_step > INT_MAX / shifted_w)
- Path B: av_image_fill_linesizes() originally had NO overflow check → integer overflow

**Fix**: Created internal image_get_linesize() with overflow check, both functions use it

---

## 24. graphparser Output Pad Check

**Commit**: 668673f10ce225d26a96f1aeb62066e8c641c85a
**File**: libavfilter/graphparser.c
**Issue**: Missing output pad existence check

**Pattern**:
- parse_outputs() → processes output link labels
- Path A: Input parsing checks pad existence
- Path B: Output parsing did NOT check if input pad exists → crash

**Fix**: Added check for input existence before processing

---

## 25. amerge Custom Layout Check

**Commit**: a3a36f059a44f04e764d841f16c87823007a71fb
**File**: libavfilter/af_amerge.c
**Issue**: Incomplete overlap check for custom layouts

**Pattern**:
- query_formats() → processes channel layouts
- Path A: Native layouts properly checked for overlap
- Path B: Custom layouts with duplicate channels NOT properly checked → crash

**Fix**: Changed overlap detection to use av_popcount64

---

## 26. unsharp Matrix Size Check

**Commit**: fbcc584d3abba475c49091ea304222a92b626026
**File**: libavfilter/vf_unsharp.c
**Issue**: Missing size validation for matrix parameters

**Pattern**:
- unsharp filter → uses matrix for processing
- Path A: Some parameters validated
- Path B: Matrix size values NOT validated → OOB access, crash

**Fix**: Added bounds checks for matrix size values (3-63)

---

## 27. HLS avoption Fields Check

**Commit**: 665f2d432ccdfef91d4b3fa640582160076b18eb
**File**: libavformat/hls.c
**Issue**: Missing NULL check before accessing priv_data_class

**Pattern**:
- hls_read_header() → accesses avoption fields
- Path A: Some avoption accesses check for NULL
- Path B: u->prot->priv_data_class NOT checked → NULL pointer exception

**Fix**: Added check for u && u->prot->priv_data_class

---

## 28. executor Mutex Check

**Commit**: 54f9469fa173394ef3a19d8c6e700bca0b8fde81
**File**: libavutil/executor.c
**Issue**: Missing mutex validity check

**Pattern**:
- av_executor_execute() → uses mutex for synchronization
- Path A: When thread_count > 0, mutex operations are valid
- Path B: When thread_count == 0, mutex operations should be skipped → using uninitialized mutex

**Fix**: Added thread_count check before mutex operations

---

## 29. buffersink alphamodes Check

**Commit**: 23b759e99ed65b8eb3eca0e976d75285d8485b80
**File**: libavfilter/buffersink.c
**Issue**: Missing alphamodes in validation check

**Pattern**:
- common_init() / vsink_query_formats() → validates format lists
- Path A: Other format list types (pixel_formats, colorspaces, colorranges) checked
- Path B: alphamodes NOT included in checks → missed validation

**Fix**: Added alphamodes/nb_alphamodes to validation conditions

---

## 30. bwdif Small Height Bounds Check

**Commit**: 5bc4a9898c806c1d532ac11712a26537acb96734
**File**: libavfilter/vf_bwdif.c
**Issue**: Missing boundary check for filter_intra with small heights

**Pattern**:
- filter_slice() → applies deinterlacing filters
- Path A: Regular frame processing has y bounds check (y < 4 || y + 5 > h)
- Path B: YADIF_FIELD_END intra mode did NOT have same bounds check → heap overflow

**Fix**: Added boundary check (y < 3 || y + 3 >= h) for filter_intra

---

## 31. dpx Stale Flag Issue

**Commit**: 9849a274dfdd3d59f8babb50fcebe2dcbdfeb2d4
**File**: libavcodec/dpx.c
**Issue**: Stale unpadded_10bit flag causing incorrect validation

**Pattern**:
- decode_frame() → processes DPX frames
- Path A: New frame should reset context state
- Path B: unpadded_10bit flag NOT reset between frames → wrong buffer validation

**Fix**: Reset unpadded_10bit = 0 at start of decode_frame

---

## 32. prores_raw Header Length Check

**Commit**: 041d4f010e9fd73d661b2fc48309dd7f548a1481
**File**: libavcodec/prores_raw.c
**Issue**: Missing header_len validation against remaining bytes

**Pattern**:
- decode_frame() → reads header_len from bitstream
- Path A: header_len checked for minimum value (< 62)
- Path B: header_len NOT checked against remaining buffer size → heap overflow

**Fix**: Added check: bytestream2_get_bytes_left(&gb) >= header_len - 2

---

## 33. zmbv realloc Return Check

**Commit**: cb0b284381ea506a54c59c4968cd2c2c937f4d75
**File**: libavcodec/zmbv.c
**Issue**: Missing av_realloc return checks

**Pattern**:
- decode_frame() → reallocates buffers
- Path A: Some allocations checked
- Path B: c->cur and c->prev realloc NOT checked → NULL pointer use, memleak

**Fix**: Added return checks for both realloc calls

---

## 34. vp56 realloc Check

**Commit**: 942babd87f18372c2b533b246a083250640466b8
**File**: libavcodec/vp56.c
**Issue**: Missing realloc checks in vp56_size_changed

**Pattern**:
- vp56_size_changed() → reallocates multiple buffers
- Path A: edge_emu_buffer_alloc checked
- Path B: above_blocks and macroblocks realloc NOT checked → NULL pointer use

**Fix**: Added NULL check for all three allocations

---

## 35. eatgv realloc Check

**Commit**: a5615b82eb116e9fd0f71f2b03c333cc31ab706a
**File**: libavcodec/eatgv.c
**Issue**: Missing realloc checks for codebook buffers

**Pattern**:
- tgv_decode_inter() → reallocates codebooks
- Path A: Some buffer allocations checked
- Path B: mv_codebook and block_codebook realloc NOT checked → NULL use

**Fix**: Added checks using av_reallocp_array

---

## 36. truemotion2 realloc Check

**Commit**: 6e07bb36393f03d16b792738196ae045fc24acb6
**File**: libavcodec/truemotion2.c
**Issue**: Missing realloc check for tokens array

**Pattern**:
- tm2_read_stream() → reallocates tokens
- Path A: Other allocations checked
- Path B: tokens realloc NOT checked → NULL pointer use

**Fix**: Added return check for av_reallocp_array

---

## 37. mov tfra Overflow Check

**Commit**: 9143ab0e5a75519c899cae2996d07b3f69bcfb24
**File**: libavformat/mov.c
**Issue**: Missing overflow check and error handling

**Pattern**:
- read_tfra() → allocates fragment index
- Path A: Some allocations use overflow-safe functions
- Path B: item_count used directly in av_mallocz without overflow check → allocation size overflow on 32-bit

**Fix**: Use av_mallocz_array and check allocation errors

---

## 38. cbs_h266 Subpic Dimension Check

**Commit**: 673862e9474cd343b686cb549ec09af68ec84d6f
**File**: libavcodec/cbs_h266_syntax_template.c
**Issue**: Missing dimension validation causing division by zero

**Pattern**:
- sps() function → processes subpic dimensions
- Path A: Some dimension values checked
- Path B: sps_subpic_width_minus1 + 1 NOT validated for zero → division by zero

**Fix**: Added validation checks for subpic dimension values

---

## 39. bytestream2 NULL Pointer Prevention

**Commit**: 6ba0b59d8b014a311f94657557769040d8305327
**File**: libavcodec/bytestream.h
**Issue**: Allowing NULL pointer in bytestream2_init

**Pattern**:
- bytestream2_init() / bytestream2_init_writer() → initializes byte context
- Path A: Most init functions check for NULL
- Path B: These functions only checked buf_size >= 0 → UB with NULL pointer

**Fix**: Added av_assert0(buf && buf_size >= 0)

---

## 40. mmxext CPU Flag Check

**Commit**: 0b51e0baea31213038d2e908be4ae0203140240f
**File**: libavutil/cpu.c
**Issue**: Missing MMXEXT in CPU flags validation

**Pattern**:
- av_force_cpu_flags() → validates CPU flags
- Path A: Other CPU flags (3DNOW, SSE, etc.) checked for dependencies
- Path B: MMXEXT NOT in validation list → incorrect flag handling

**Fix**: Added AV_CPU_FLAG_MMXEXT to validation check

---

## Summary

Found 40 vulnerabilities matching the "miss check" pattern in FFmpeg git history.

Key patterns observed:
1. **CVE-numbered issues**: CVE-2023-6603, CVE-2023-6602, CVE-2022-2566, CVE-2013-0868 similar
2. **Memory errors**: heap overflow, NULL pointer dereference, division by zero
3. **Common scenarios**:
   - Allocation return not checked (av_malloc, av_realloc)
   - Index/bounds not validated before array access
   - Path-specific check missing when other paths have it
   - Return values not propagated

Most clear examples of the specific pattern (two paths, one checked, one not):
- #4 (US vs UK path in parse_itut_t35_metadata)
- #5 (sscanf in init vs parse_channel_name)
- #13 (HTTP connection reuse path missing s->hd check)
- #30 (bwdif filter_intra missing bounds check that filter_edge has)
- #23 (av_image_fill_linesizes missing overflow check that av_image_get_linesize has)