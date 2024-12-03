# -*- coding: utf-8 -*-

import hashlib
import hmac
import json
import time
import logging
import requests
from datetime import datetime
from logging.handlers import RotatingFileHandler

# 配置日志
logger = logging.getLogger('dns_updater')
logger.setLevel(logging.INFO)

# 创建一个文件处理器 (RotatingFileHandler) 并配置日志分片
log_file = '/var/log/dns_updater.log'
file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5)
file_handler.setLevel(logging.INFO)

# 创建一个控制台处理器 (StreamHandler)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# 定义日志输出格式
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# 将格式化器应用到各个处理器
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# 将处理器添加到记录器
logger.addHandler(file_handler)
logger.addHandler(console_handler)

class DNSUpdater:
    def __init__(self, secret_id, secret_key, domain, record_name, log_file="dns_updater.log"):
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.domain = domain
        self.record_name = record_name
        self.version = "2021-03-23"
        self.service = "dnspod"
        self.host = "dnspod.tencentcloudapi.com"
        self.endpoint = "https://" + self.host
        self.region = ""

    def sign(self, key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def compute_signature(self, action, params, timestamp):
        algorithm = "TC3-HMAC-SHA256"
        date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")

        http_request_method = "POST"
        canonical_uri = "/"
        canonical_querystring = ""
        payload = json.dumps(params)
        ct = "application/json; charset=utf-8"
        canonical_headers = f"content-type:{ct}\nhost:{self.host}\nx-tc-action:{action.lower()}\n"

        signed_headers = "content-type;host;x-tc-action"
        hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        canonical_request = (
            f"{http_request_method}\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{hashed_request_payload}"
        )

        credential_scope = f"{date}/{self.service}/tc3_request"
        hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        string_to_sign = (
            f"{algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}"
        )

        secret_date = self.sign(("TC3" + self.secret_key).encode("utf-8"), date)
        secret_service = self.sign(secret_date, self.service)
        secret_signing = self.sign(secret_service, "tc3_request")
        signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        authorization = (
            f"{algorithm} Credential={self.secret_id}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )

        return authorization, payload

    def make_request(self, action, params):
        timestamp = int(time.time())
        authorization, payload = self.compute_signature(action, params, timestamp)

        headers = {
            "Authorization": authorization,
            "Content-Type": "application/json; charset=utf-8",
            "Host": self.host,
            "X-TC-Action": action,
            "X-TC-Timestamp": str(timestamp),
            "X-TC-Version": self.version,
            "X-TC-Language": "zh-CN",
        }
        if self.region:
            headers["X-TC-Region"] = self.region
        try:
            response = requests.post(self.endpoint, headers=headers, data=payload)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Request error: {e}")
            return None

    def get_record_list(self):
        action = "DescribeRecordList"
        params = {"Domain": self.domain}
        return self.make_request(action, params)

    def find_record_by_name(self, records):
        record_list = records.get("Response", {}).get("RecordList", [])
        for record in record_list:
            if record["Name"] == self.record_name:
                return record
        return None

    def modify_record(self, record_id, ip):
        action = "ModifyRecord"
        params = {
            "Domain": self.domain,
            "RecordId": record_id,
            "SubDomain": self.record_name,
            "Value": ip,
            "RecordType": "A",
            "RecordLine": "默认",
        }
        return self.make_request(action, params)

    def get_public_ip(self):
        try:
            response = requests.get("https://httpbin.org/ip")
            response.raise_for_status()
            return response.json().get("origin")
        except requests.RequestException as e:
            self.logger.error(f"IP fetch error: {e}")
            return None

    def report_ip(self):
        logger.info("Getting public IP...")
        nas_ip = self.get_public_ip()
        if not nas_ip:
            logger.error("Failed to get public IP.")
            return
        logger.info(f"The current public IP is: {nas_ip}.")
        records = self.get_record_list()
        if not records:
            logger.error("Failed to get DNS records.")
            return
        nas_record = self.find_record_by_name(records)
        if not nas_record:
            logger.error("Record not found.")
            return
        if nas_record.get("Value", "") == nas_ip:
            logger.info("The domain name resolution record address is already up to date")
            return
        logger.info(f"Updating the DNS record for {self.record_name}.{self.domain} to {nas_ip}...")
        record_id = nas_record.get("RecordId", "")
        status = self.modify_record(record_id, ip=nas_ip)
        if status and status.get("Response", {}).get("RecordId"):
            logger.info("Record modified successfully.")
        else:
            logger.error(f"Failed to modify record: {status}")

    def run_loop(self):
        while True:
            self.report_ip()
            time.sleep(600)

def main():
    secret_id = "dnspod_secret_id"
    secret_key = "dnspod_secret_key"
    domain = "domian.com"
    record_name = "www"
    updater = DNSUpdater(secret_id, secret_key, domain, record_name)
    updater.run_loop()

if __name__ == "__main__":
    main()
