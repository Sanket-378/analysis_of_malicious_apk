from google.colab import files

print("Please upload your APK file.")
uploaded = files.upload()
apk_path = list(uploaded.keys())[0]

import os
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.misc import AnalyzeAPK

def extract_features(apk_path):
    features = {
        "js_inf_len": 0,
        "web_redirect": 0,
        "https": 0,
        "gsafe_brow": 0,
        "js_input_val": 0
    }
    try:
        apk = APK(apk_path)
        dex = DalvikVMFormat(apk.get_dex())
        all_strings = set()
        for string in dex.get_strings():
            all_strings.add(string)
        urls = [s for s in all_strings if s.startswith("http")]
        features["js_inf_len"] = sum(1 for s in all_strings if "<script" in s.lower())
        features["https"] = len([url for url in urls if url.startswith("https")])
        features["web_redirect"] = len([url for url in urls if "redirect" in url.lower()])
        features["gsafe_brow"] = len([url for url in urls if "google" in url.lower()])
        features["js_input_val"] = len([url for url in urls if "input" in url.lower()])
    except Exception as e:
        features = {"error": str(e)}
    return features

print("Analyzing the APK file. Please wait...")
features = extract_features(apk_path)

print("\nExtracted Features:")
for key, value in features.items():
    print(f"{key}: {value}")