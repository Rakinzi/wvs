import re
import hashlib
import ipaddress
import logging
import string
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
import requests

from app.settings import settings


class AI_Scanner:
    def __init__(self):
        self.model_path = Path(__file__).resolve().parent.parent / "model" / "eTc.sav"
        self.model = None
        self.model_available = self.model_path.exists()
        self.hf_model = settings.huggingface_url_model
        self.hf_api_token = settings.huggingface_api_token
        self.hf_timeout_seconds = settings.huggingface_timeout_seconds

        if not self.model_available:
            logging.warning("AI model file not found: %s", self.model_path)
        else:
            self.model = joblib.load(self.model_path)

    def _hf_predict(self, url):
        if not self.hf_api_token:
            return None, "unavailable", "none"

        endpoint = f"https://api-inference.huggingface.co/models/{self.hf_model}"
        headers = {"Authorization": f"Bearer {self.hf_api_token}"}
        payload = {
            "inputs": url,
            "options": {"wait_for_model": True},
        }

        try:
            response = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=self.hf_timeout_seconds,
            )
            response.raise_for_status()
            body = response.json()
        except Exception as exc:
            logging.warning("Hugging Face inference failed for %s: %s", url, exc)
            return None, "unavailable", "huggingface"

        candidates = []
        if isinstance(body, list):
            if body and isinstance(body[0], list):
                candidates = body[0]
            elif body and isinstance(body[0], dict):
                candidates = body

        if not candidates:
            return None, "unknown", "huggingface"

        top = max(candidates, key=lambda item: item.get("score", 0))
        raw_label = str(top.get("label", "unknown")).strip().lower()
        label_mapping = {
            "benign": "benign",
            "safe": "benign",
            "phishing": "phishing",
            "malware": "malware",
            "defacement": "defacement",
            "malicious": "malware",
        }
        normalized_label = label_mapping.get(raw_label, raw_label)
        class_mapping = {"benign": 0, "defacement": 1, "phishing": 2, "malware": 3}
        return class_mapping.get(normalized_label), normalized_label, "huggingface"

    def get_url_length(self, url):
        prefixes = ["http://", "https://"]
        for prefix in prefixes:
            if url.startswith(prefix):
                url = url[len(prefix) :]

        url = url.replace("www.", "")
        return len(url)

    def count_letters(self, url):
        num_letters = sum(char.isalpha() for char in url)
        return num_letters

    def count_digits(self, url):
        num_digits = sum(char.isdigit() for char in url)
        return num_digits

    def count_special_chars(self, url):
        special_chars = set(string.punctuation)
        num_special_chars = sum(char in special_chars for char in url)
        return num_special_chars

    def has_shortening_service(self, url):
        pattern = re.compile(r"https?://(?:www\.)?(?:\w+\.)*(\w+)\.\w+")
        match = pattern.search(url)

        if match:
            domain = match.group(1)
            common_shortening_services = [
                "bit",
                "goo",
                "tinyurl",
                "ow",
                "t",
                "is",
                "cli",
                "yfrog",
                "migre",
                "ff",
                "url4",
                "twit",
                "su",
                "snipurl",
                "short",
                "BudURL",
                "ping",
                "post",
                "Just",
                "bkite",
                "snipr",
                "fic",
                "loopt",
                "doiop",
                "short",
                "kl",
                "wp",
                "rubyurl",
                "om",
                "to",
                "bit",
                "t",
                "lnkd",
                "db",
                "qr",
                "adf",
                "goo",
                "bitly",
                "cur",
                "tinyurl",
                "ow",
                "bit",
                "ity",
                "q",
                "is",
                "po",
                "bc",
                "twitthis",
                "u",
                "j",
                "buzurl",
                "cutt",
                "u",
                "yourls",
                "x",
                "prettylinkpro",
                "scrnch",
                "filoops",
                "vzturl",
                "qr",
                "1url",
                "tweez",
                "v",
                "tr",
                "link",
                "zip",
            ]

            if domain.lower() in common_shortening_services:
                return 1
        return 0

    def abnormal_url(self, url):
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            hostname = str(hostname)
            match = re.search(hostname, url)
            if match:
                return 1
        return 0

    def secure_http(self, url):
        return int(urlparse(url).scheme == "https")

    def have_ip_address(self, url):
        try:
            parsed_url = urlparse(url)
            if parsed_url.hostname:
                ip = ipaddress.ip_address(parsed_url.hostname)
                return isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
        except ValueError:
            pass  # Invalid hostname or IP address

        return 0

    def get_url_region(self, primary_domain):
        ccTLD_to_region = {
            ".ac": "Ascension Island",
            ".ad": "Andorra",
            ".ae": "United Arab Emirates",
            ".af": "Afghanistan",
            ".ag": "Antigua and Barbuda",
            ".ai": "Anguilla",
            ".al": "Albania",
            ".am": "Armenia",
            ".an": "Netherlands Antilles",
            ".ao": "Angola",
            ".aq": "Antarctica",
            ".ar": "Argentina",
            ".as": "American Samoa",
            ".at": "Austria",
            ".au": "Australia",
            ".aw": "Aruba",
            ".ax": "Åland Islands",
            ".az": "Azerbaijan",
            ".ba": "Bosnia and Herzegovina",
            ".bb": "Barbados",
            ".bd": "Bangladesh",
            ".be": "Belgium",
            ".bf": "Burkina Faso",
            ".bg": "Bulgaria",
            ".bh": "Bahrain",
            ".bi": "Burundi",
            ".bj": "Benin",
            ".bm": "Bermuda",
            ".bn": "Brunei Darussalam",
            ".bo": "Bolivia",
            ".br": "Brazil",
            ".bs": "Bahamas",
            ".bt": "Bhutan",
            ".bv": "Bouvet Island",
            ".bw": "Botswana",
            ".by": "Belarus",
            ".bz": "Belize",
            ".ca": "Canada",
            ".cc": "Cocos Islands",
            ".cd": "Democratic Republic of the Congo",
            ".cf": "Central African Republic",
            ".cg": "Republic of the Congo",
            ".ch": "Switzerland",
            ".ci": "Côte d'Ivoire",
            ".ck": "Cook Islands",
            ".cl": "Chile",
            ".cm": "Cameroon",
            ".cn": "China",
            ".co": "Colombia",
            ".cr": "Costa Rica",
            ".cu": "Cuba",
            ".cv": "Cape Verde",
            ".cw": "Curaçao",
            ".cx": "Christmas Island",
            ".cy": "Cyprus",
            ".cz": "Czech Republic",
            ".de": "Germany",
            ".dj": "Djibouti",
            ".dk": "Denmark",
            ".dm": "Dominica",
            ".do": "Dominican Republic",
            ".dz": "Algeria",
            ".ec": "Ecuador",
            ".ee": "Estonia",
            ".eg": "Egypt",
            ".er": "Eritrea",
            ".es": "Spain",
            ".et": "Ethiopia",
            ".eu": "European Union",
            ".fi": "Finland",
            ".fj": "Fiji",
            ".fk": "Falkland Islands",
            ".fm": "Federated States of Micronesia",
            ".fo": "Faroe Islands",
            ".fr": "France",
            ".ga": "Gabon",
            ".gb": "United Kingdom",
            ".gd": "Grenada",
            ".ge": "Georgia",
            ".gf": "French Guiana",
            ".gg": "Guernsey",
            ".gh": "Ghana",
            ".gi": "Gibraltar",
            ".gl": "Greenland",
            ".gm": "Gambia",
            ".gn": "Guinea",
            ".gp": "Guadeloupe",
            ".gq": "Equatorial Guinea",
            ".gr": "Greece",
            ".gs": "South Georgia and the South Sandwich Islands",
            ".gt": "Guatemala",
            ".gu": "Guam",
            ".gw": "Guinea-Bissau",
            ".gy": "Guyana",
            ".hk": "Hong Kong",
            ".hm": "Heard Island and McDonald Islands",
            ".hn": "Honduras",
            ".hr": "Croatia",
            ".ht": "Haiti",
            ".hu": "Hungary",
            ".id": "Indonesia",
            ".ie": "Ireland",
            ".il": "Israel",
            ".im": "Isle of Man",
            ".in": "India",
            ".io": "British Indian Ocean Territory",
            ".iq": "Iraq",
            ".ir": "Iran",
            ".is": "Iceland",
            ".it": "Italy",
            ".je": "Jersey",
            ".jm": "Jamaica",
            ".jo": "Jordan",
            ".jp": "Japan",
            ".ke": "Kenya",
            ".kg": "Kyrgyzstan",
            ".kh": "Cambodia",
            ".ki": "Kiribati",
            ".km": "Comoros",
            ".kn": "Saint Kitts and Nevis",
            ".kp": "Democratic People's Republic of Korea (North Korea)",
            ".kr": "Republic of Korea (South Korea)",
            ".kw": "Kuwait",
            ".ky": "Cayman Islands",
            ".kz": "Kazakhstan",
            ".la": "Laos",
            ".lb": "Lebanon",
            ".lc": "Saint Lucia",
            ".li": "Liechtenstein",
            ".lk": "Sri Lanka",
            ".lr": "Liberia",
            ".ls": "Lesotho",
            ".lt": "Lithuania",
            ".lu": "Luxembourg",
            ".lv": "Latvia",
            ".ly": "Libya",
            ".ma": "Morocco",
            ".mc": "Monaco",
            ".md": "Moldova",
            ".me": "Montenegro",
            ".mf": "Saint Martin (French part)",
            ".mg": "Madagascar",
            ".mh": "Marshall Islands",
            ".mk": "North Macedonia",
            ".ml": "Mali",
            ".mm": "Myanmar",
            ".mn": "Mongolia",
            ".mo": "Macao",
            ".mp": "Northern Mariana Islands",
            ".mq": "Martinique",
            ".mr": "Mauritania",
            ".ms": "Montserrat",
            ".mt": "Malta",
            ".mu": "Mauritius",
            ".mv": "Maldives",
            ".mw": "Malawi",
            ".mx": "Mexico",
            ".my": "Malaysia",
            ".mz": "Mozambique",
            ".na": "Namibia",
            ".nc": "New Caledonia",
            ".ne": "Niger",
            ".nf": "Norfolk Island",
            ".ng": "Nigeria",
            ".ni": "Nicaragua",
            ".nl": "Netherlands",
            ".no": "Norway",
            ".np": "Nepal",
            ".nr": "Nauru",
            ".nu": "Niue",
            ".nz": "New Zealand",
            ".om": "Oman",
            ".pa": "Panama",
            ".pe": "Peru",
            ".pf": "French Polynesia",
            ".pg": "Papua New Guinea",
            ".ph": "Philippines",
            ".pk": "Pakistan",
            ".pl": "Poland",
            ".pm": "Saint Pierre and Miquelon",
            ".pn": "Pitcairn",
            ".pr": "Puerto Rico",
            ".ps": "Palestinian Territory",
            ".pt": "Portugal",
            ".pw": "Palau",
            ".py": "Paraguay",
            ".qa": "Qatar",
            ".re": "Réunion",
            ".ro": "Romania",
            ".rs": "Serbia",
            ".ru": "Russia",
            ".rw": "Rwanda",
            ".sa": "Saudi Arabia",
            ".sb": "Solomon Islands",
            ".sc": "Seychelles",
            ".sd": "Sudan",
            ".se": "Sweden",
            ".sg": "Singapore",
            ".sh": "Saint Helena",
            ".si": "Slovenia",
            ".sj": "Svalbard and Jan Mayen",
            ".sk": "Slovakia",
            ".sl": "Sierra Leone",
            ".sm": "San Marino",
            ".sn": "Senegal",
            ".so": "Somalia",
            ".sr": "Suriname",
            ".ss": "South Sudan",
            ".st": "São Tomé and Príncipe",
            ".sv": "El Salvador",
            ".sx": "Sint Maarten (Dutch part)",
            ".sy": "Syria",
            ".sz": "Eswatini",
            ".tc": "Turks and Caicos Islands",
            ".td": "Chad",
            ".tf": "French Southern Territories",
            ".tg": "Togo",
            ".th": "Thailand",
            ".tj": "Tajikistan",
            ".tk": "Tokelau",
            ".tl": "Timor-Leste",
            ".tm": "Turkmenistan",
            ".tn": "Tunisia",
            ".to": "Tonga",
            ".tr": "Turkey",
            ".tt": "Trinidad and Tobago",
            ".tv": "Tuvalu",
            ".tw": "Taiwan",
            ".tz": "Tanzania",
            ".ua": "Ukraine",
            ".ug": "Uganda",
            ".uk": "United Kingdom",
            ".us": "United States",
            ".uy": "Uruguay",
            ".uz": "Uzbekistan",
            ".va": "Vatican City",
            ".vc": "Saint Vincent and the Grenadines",
            ".ve": "Venezuela",
            ".vg": "British Virgin Islands",
            ".vi": "U.S. Virgin Islands",
            ".vn": "Vietnam",
            ".vu": "Vanuatu",
            ".wf": "Wallis and Futuna",
            ".ws": "Samoa",
            ".ye": "Yemen",
            ".yt": "Mayotte",
            ".za": "South Africa",
            ".zm": "Zambia",
            ".zw": "Zimbabwe",
        }

        for ccTLD in ccTLD_to_region:
            if primary_domain.endswith(ccTLD):
                return ccTLD_to_region[ccTLD]

        return "Global"

    def get_numerical_values(self, url):
        url = url.replace("www.", "")
        url_length = self.get_url_length(url)
        num_letters = self.count_letters(url)
        num_digits = self.count_digits(url)
        num_special_chars = self.count_special_chars(url)
        shortening_service = self.has_shortening_service(url)
        abnormal_url = self.abnormal_url(url)
        secure_http = self.secure_http(url)
        have_ip_address = self.have_ip_address(url)

        parsed_url = urlparse(url)
        root_domain = parsed_url.netloc.split(".")[-2]
        url_region = self.get_url_region(root_domain)

        return {
            "url_len": url_length,
            "letters_count": num_letters,
            "digits_count": num_digits,
            "special_chars_count": num_special_chars,
            "shortened": shortening_service,
            "abnormal": abnormal_url,
            "secure_http": secure_http,
            "have_ip": have_ip_address,
            "url_region": self.hash_encode(url_region),
            "root_domain": self.hash_encode(root_domain),
        }

    def hash_encode(self, category):
        hash_object = hashlib.md5(category.encode())
        return int(hash_object.hexdigest(), 16) % (10**8)

    def model_predict(self, url):
        if not self.model_available or self.model is None:
            return self._hf_predict(url)

        class_mapping = {0: "benign", 1: "defacement", 2: "phishing", 3: "malware"}
        numerical_values = self.get_numerical_values(url)
        prediction_int = self.model.predict(
            np.array(list(numerical_values.values())).reshape(1, -1)
        )[0]
        prediction_label = class_mapping.get(prediction_int, "unknown")
        return prediction_int, prediction_label, "local_model"
    
