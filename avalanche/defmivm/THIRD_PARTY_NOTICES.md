# Third-party notice

The Rust RPCChainVM boundary is a focused fork of Ava Labs'
`ava-labs/avalanche-rs` at commit
`1bfa6d5e87e8c5ad0b855a928a3b447e594daa63`. Its exact provenance and protocol
adaptations are recorded in `rust/vendor/avalanche-rs-qomm/UPSTREAM.md`.

The fork is distributed under the Ava Labs Ecosystem License 1.1. The complete,
unmodified license is retained at `rust/vendor/avalanche-rs-qomm/LICENSE` and
must accompany source and binary distributions. Production use must remain on
the Avalanche Authorized Platform as defined by that license.

RPCChainVM protocol schemas are pinned to AvalancheGo v1.14.2, commit
`6e5acf909c7a16b991142d6b3979bac5699bdb68`. The full acceptance artifact
records the exact AvalancheGo and network-runner binary hashes used with the
fork. Those schemas, including the HTTP reader and response-writer callback
services, retain AvalancheGo's BSD 3-Clause license at
`rust/vendor/avalanche-rs-qomm/AVALANCHEGO_LICENSE`.

## Triptych / native note membership version 2

The note membership adapter uses the unchanged Tari Project Triptych library,
commit `bf0cb42fff55636a8bb037020411fb3a050af23f`, through its parallel RingCT
API. Source: https://github.com/tari-project/triptych . The algorithm is a pinned
Git dependency, not copied or modified here. The upstream implementation is
experimental and explicitly not suitable for production; no upstream audit
or endorsement is implied. The following notice accompanies binary images.

BSD 3-Clause License

Copyright (c) 2024, The Tari Project
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
