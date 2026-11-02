# WebGPU source-level security audit (WebContent RCE / GPUProcess memory-corruption)

Checkout: `/Users/dawgyg/webkit_work/WebKit_fresh`
Scope: `Source/WebCore/Modules/WebGPU` (JS-facing) + `Source/WebCore/Modules/WebGPU/Implementation` (in-proc proxy) + `Source/WebKit/{WebProcess,GPUProcess}/**/WebGPU` (IPC) + `Source/WebGPU/WebGPU/*.mm` (Metal backend, where spec validation lives). Method: read .cpp/.mm/.h, no binary RE. (WebCodecs deliberately untouched — Codex owns it.)

## Architecture (why the classic getMappedRange-aliasing UAF does NOT apply here)
JS `GPUBuffer` (`Modules/WebGPU/GPUBuffer.cpp`) → abstract `WebGPU::Buffer` → either `BufferImpl` (in-process C-API) or `RemoteBufferProxy` (IPC to GPUProcess) → GPUProcess `RemoteBuffer` → `BufferImpl` → `wgpuBuffer*` → `WebGPU::Buffer` in `Buffer.mm` (Metal).

`getMappedRange()` never hands JS a pointer aliasing live GPU/shared memory. `makeArrayBuffer()` (GPUBuffer.cpp:97-111) always does `ArrayBuffer::create(source)`, a **byte copy**; on `unmap()`/`destroy()` the copy is written back and detached. This copy model is the load-bearing mitigation for bug classes 1/2/3/5.

## Closure table

| API op | attacker input | backing-memory sink | free/detach/race event | ordered/validated (cite) |
|---|---|---|---|---|
| `getMappedRange(offset,size)` | offset/size | `ArrayBuffer::create` copy of `mappedRange.first(size)` | unmap/destroy detaches | **CLOSED** WebContent bounds `GPUBuffer.cpp:139-167` (checkedSum, `offset%8`, `size%4`, `offset>=m_mappedRangeOffset`, `endOffset<=mappedRangeSize+off` & `<=bufferSize`, `containsRange` overlap). GPUProcess re-validates `Buffer.mm:261-286` (`validateGetMappedRange`, checkedSum, overlap). Returns a copy, not an alias. |
| `unmap()` / `destroy()` | — | copy-back `copyFrom` + `transferTo` detach | JS holds ArrayBuffer after | **CLOSED** every entry in `m_arrayBuffers` copied back then `unpin()`+`transferTo` (detach) `GPUBuffer.cpp:216-227`; copy is independent memory so no UAF even if not detached. `destroy` calls `internalUnmap` first `GPUBuffer.cpp:230-236`. |
| `mapAsync()` pending-map race | mode/offset/size + unmap/destroy during pending | resolve/reject callback | unmap nulls `m_pendingMapPromise` & rejects; destroy sets `m_destroyed` | **CLOSED** callback re-checks `!m_pendingMapPromise` → resolve/reject-by-destroyed `GPUBuffer.cpp:73-94`; GPUProcess re-checks `m_state==MappingPending` before Mapped `Buffer.mm:392-399`; state guarded so Destroyed stays Destroyed `Buffer.mm:427-431`. `protect(*this)` strong-ref keeps object alive across async. |
| `device.destroy()` device-lost | — | all mapped buffers | outstanding ArrayBuffers | **CLOSED** `GPUDevice.cpp:136-143` iterates `m_buffersToUnmap` (WeakHashSet, `GPUDevice.h:178`) → `buffer->destroy()` → detach-all. |
| IPC write-back `RemoteBuffer::copy` / `copyWithCopy` | Vector/SharedMemory + offset | `memcpySpan(buffer.subspan(offset), data)` | — | **CLOSED** `RemoteBuffer.cpp:105-120,122-155` gate on `m_isMapped && MapMode::Write && !m_pendingMap`, `checkedSum<size_t>(offset,dataSize)` overflow + `> buffer.size()` bail. |
| IPC reply `RemoteBufferProxy::getMappedRange` | offset/size vs GPUProcess reply | `data->mutableSpan().subspan(offset)` | — | **CLOSED** resets `offset=0` (proxy replies already offset-based) + `offsetOrSizeExceedsBounds(data->size(),0,size)` `RemoteBufferProxy.cpp:64-81`. |
| `queue.writeBuffer(buf,off,data)` | off/size, data span | shared/managed memcpy + private blit | — | **CLOSED** `validateWriteBuffer` `Queue.mm:445-453` (checkedSum vs `currentSize()`, `%4`); source len = real span size. |
| `queue.writeTexture(dst,data,layout,size)` | bytesPerRow/rowsPerImage/origin/copySize | replaceRegion / copyFromBuffer blit | — | **CLOSED** `Texture::errorValidatingLinearTextureData` `Texture.mm:4030-4096` (`checkedProduct`/`CheckedUint64` `offset+requiredBytesInCopy <= byteSize`) + `errorValidatingTextureCopyRange` `Texture.mm:4007-4019` (origin+copySize vs mip-specific extent). Every intermediate product checkedProduct-guarded. |
| `copyBufferToBuffer` | src/dst off, size | Metal blit | — | **CLOSED** `CommandEncoder.mm:864-885` (checkedSum vs `initialSize()`, `%4`). |
| `copyBufferToTexture`/`copyTextureToBuffer`/`copyTextureToTexture` | off/rects/origin | Metal blit | — | **CLOSED** same two validators + per-loop checkedProduct/checkedSum; C2T validates both textures + self-overlap `CommandEncoder.mm:1844-2013`. |
| `clearBuffer` / `resolveQuerySet` | off/size / query idx | fill / resolve | — | **CLOSED** `CommandEncoder.mm:2050-2052` / `2244-2259` (checkedSum/checkedProduct, `%256`). |
| Texture view create | baseMip/mipCount/baseLayer/layerCount | `newTextureViewWithPixelFormat:levels:slices:` | — | **CLOSED** `Texture.mm:3165-3173` (checkedSum vs parent mip/array counts) before the Metal call; UNDEFINED-count resolution checkedDifference `3049-3104`. |
| BindGroup entry (type confusion, class 6) | resource variant vs layout | argument-buffer encode | — | **CLOSED** each of 5 variants matched to layout `std::variant` alt via `std::get_if`/`hasBinding` before use `BindGroup.mm:621-625,1150-1153,1226-1229,1251-1256,1270`; exactly-one gate `1127`; buffer `offset>=length` `1181`, `entrySize+entryOffset>length` with `entrySize` pre-capped to limits `1197-1206`. |
| RenderBundle dynamic offsets | per-draw dynamic offsets | `updateVertexOffsets` writes into offsets buffer | two-phase replay desync | **CLOSED** two-phase: pass1 accumulates, `finish()` allocs buffer = total `RenderBundleEncoder.mm:907-908`, pass2 writes at pre-increment base; inner writes size-checked `PipelineLayout.mm:293,304-305` (return false, not OOB); counts validated by `errorValidatingBindGroup` upstream. |

## Candidate bugs
**None submittable.** No web-reachable OOB/UAF/type-confusion/overflow gap found. The module reflects heavy prior hardening: WTF `Checked<>`/`checkedSum`/`checkedProduct`/`checkedDifference` with explicit `.hasOverflowed()` bailouts on essentially every attacker-controlled size/offset product, layered WebContent+GPUProcess double validation, and a copy-not-alias mapping model.

### Low-value residuals (DoS at most, NOT memory corruption — do not file)
- `span<T>(MTLBuffer, byteOffset)` `Buffer.mm:54-59` calls `subspan(byteOffset)` before the length guard; callers (index/indirect validation) bound `byteOffset` upstream. `makeSpanFromBuffer` `RenderBundleEncoder.mm:276-284` DOES guard the underflow. A `std::span::subspan(offset>size)` can RELEASE_ASSERT = renderer/GPUProcess crash, not corruption.
- `BufferImpl::copyFrom` is `RELEASE_ASSERT_NOT_REACHED()` on the non-WEBGPU_SWIFT in-process path `WebGPUBufferImpl.cpp:98-101`; reachable only in an in-process-WebGPU non-Swift build (not GPUProcess Safari). Crash, not corruption.

## Next less-fuzzed module (higher EV than continuing here)
1. **`Source/WebGPU/WGSL/`** — the WGSL shader compiler (lexer/parser/type-checker/Metal codegen). Web-reachable via `createShaderModule`, far larger and more complex than the CAPI-validation layer audited here, and the classic place for compiler memory bugs (unbounded recursion, const-eval overflow, symbol-table confusion). Recommend a dedicated lane + the existing ASan build (`WebKitBuild_ASan`) fuzzing `wgslc`/shader compile.
2. **`ExternalTexture.mm` + `PresentationContextIOSurface.mm`** — IOSurface/CVPixelBuffer import path (`importExternalTexture`), attacker-influenced surface geometry crossing into Metal; a different (0-copy) memory model than the buffer path.
3. **`RenderPassEncoder.mm` draw-indirect / index-buffer validation** — the `verifyIndexBufferData`/indirect slow-path (`Buffer.mm:514-642`) has `firstIndex+indexCount` uint32 arithmetic; bounded here but the indirect-args GPU-readback validation is intricate and worth a focused pass.

## How to confirm any future candidate (ASan build available)
`WebKit_fresh/WebKitBuild_ASan` exists. Minimal repro harness: an HTML page that (a) `navigator.gpu.requestAdapter()/requestDevice()`, (b) exercises the suspect call with boundary offsets/sizes, (c) drives `mapAsync`→`unmap`/`destroy` re-entrancy via promise `.then`. Load in the ASan WebKitTestRunner; ASan reports the OOB frame. No candidate warranted this yet.
