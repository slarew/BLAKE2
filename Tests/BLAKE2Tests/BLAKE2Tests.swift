// SPDX-License-Identifier: CC0-1.0 OR Apache-2.0 OR OpenSSL
// Copyright 2021 Stephen Larew

import XCTest
import BLAKE2

final class BLAKE2Tests: XCTestCase {
  func testBasics() {
    let helloDigest = Data(base64Encoded: "5M+jmj03vjHFlgnoB5cHmcqmihm/qhUTXxZQheAdQaZboeGxRq62vQCStJ6sIUwQPM+jo2WVS7vlL3Sis2IMlA==")!
    let data = "hello".data(using: .utf8)!
    var h = BLAKE2b<BLAKE2b512Digest>()
    h.update(data: data)
    let d1 = h.finalize()
    XCTAssert(d1.elementsEqual(helloDigest))
    let d2 = BLAKE2b<BLAKE2b512Digest>.hash(data: data)
    XCTAssertEqual(d1, d2)
  }

  func testKeyed() {
    // in: 000102030405060708090a0b0c0d0e0f
    // key:  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
    // hash:  a0c65bddde8adef57282b04b11e7bc8aab105b99231b750c021f4a735cb1bcfab87553bba3abb0c3e64a0b6955285185a0bd35fb8cfde557329bebb1f629ee93
    let data = Data(base64Encoded: "AAECAwQFBgcICQoLDA0ODw==")!
    let key = Data(base64Encoded: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==")!
    let expDigest = Data(base64Encoded: "oMZb3d6K3vVygrBLEee8iqsQW5kjG3UMAh9Kc1yxvPq4dVO7o6uww+ZKC2lVKFGFoL01+4z95Vcym+ux9inukw==")!
    var h = BLAKE2b<BLAKE2b512Digest>(key: BLAKE2b<BLAKE2b512Digest>.Key(data: key))
    h.update(data: data)
    let actDigest = h.finalize()
    XCTAssert(actDigest.elementsEqual(expDigest))
  }
}
