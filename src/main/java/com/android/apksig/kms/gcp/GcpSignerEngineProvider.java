/*
 * Copyright (C) 2024 The Android Open Source Project
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

package com.android.apksig.kms.gcp;

import com.android.apksig.KeyConfig;
import com.android.apksig.SignerEngine;
import com.android.apksig.kms.KmsSignerEngineProvider;
import com.android.apksig.kms.KmsType;

import java.security.spec.AlgorithmParameterSpec;

public class GcpSignerEngineProvider implements KmsSignerEngineProvider {

    @Override
    public SignerEngine getInstance(
            KeyConfig.Kms kmsConfig,
            String jcaSignatureAlgorithm,
            AlgorithmParameterSpec algorithmParameterSpec) {
        return new GcpSignerEngine(kmsConfig.keyAlias);
    }

    @Override
    public String getKmsType() {
        return KmsType.GCP;
    }
}