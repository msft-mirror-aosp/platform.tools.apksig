/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.apksig.internal.apk.v3;

import com.android.apksig.internal.util.AndroidSdkVersion;

/** Constants used by the V3 Signature Scheme signing and verification. */
public class V3SchemeConstants {
    private V3SchemeConstants() {}

    public static final int APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0;
    public static final int APK_SIGNATURE_SCHEME_V31_BLOCK_ID = 0x1b93ad61;
    public static final int PROOF_OF_ROTATION_ATTR_ID = 0x3ba06f8c;

    public static final int MIN_SDK_WITH_V3_SUPPORT = AndroidSdkVersion.P;
    public static final int MIN_SDK_WITH_V31_SUPPORT = AndroidSdkVersion.T;
    // TODO(b/192301300): Once the signing config has been updated to support specifying a
    // minSdkVersion for rotation this should be updated to T.
    public static final int DEFAULT_ROTATION_MIN_SDK_VERSION  = AndroidSdkVersion.P;

    /**
     * This attribute is intended to be written to the V3.0 signer block as an additional attribute
     * whose value is the minimum SDK version supported for rotation by the V3.1 signing block. If
     * this value is set to X and a v3.1 signing block does not exist, or the minimum SDK version
     * for rotation in the v3.1 signing block is not X, then the APK should be rejected.
     */
    public static final int ROTATION_MIN_SDK_VERSION_ATTR_ID = 0x559f8b02;
}
