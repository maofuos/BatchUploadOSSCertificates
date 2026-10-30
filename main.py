import json
import os
import sys
import time
import traceback
from datetime import datetime
from typing import Optional, List

import oss2
import requests
from oss2.models import CnameInfo
from requests import HTTPError, Timeout, RequestException


def _request(method, url, retries=3, **kwargs):
    for attempt in range(retries):
        try:
            response = requests.request(method, url, **kwargs)
            return response
        except (HTTPError, Timeout) as e:
            print("Attempt {} failed: {}".format(attempt + 1, e))
            time.sleep(2 ** attempt)  # Exponential backoff
        except RequestException as e:
            print("Request failed: {}".format(e))
            break
    return None


class OSS:
    def __init__(self, access_key_id, access_key_secret, endpoint, bucket_name, region):
        self.auth = oss2.AuthV4(access_key_id, access_key_secret)
        self.endpoint = endpoint
        self.bucket_name = bucket_name
        self.region = region
        self.bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name=self.bucket_name, region=self.region)

    def run_update(self, target_cname: str, private_key: str, certificate: str):
        cname_info = self._get_matched_cname(target_cname)
        if cname_info and private_key and certificate:
            self._update_cname(cname_info, private_key, certificate)
        else:
            print(target_cname+"未找到匹配的自定义域名或证书信息不完整")
            sys.exit(1)

    def _get_matched_cname(self, target_cname: str) -> Optional[CnameInfo]:
        cname_list = self.get_cname_info()
        for c in cname_list:
            if c.domain == target_cname:
                return c
        return None

    def get_cname_info(self, isprint: bool = False) -> List[CnameInfo]:
        list_result = self.bucket.list_bucket_cname()
        if isprint:
            for c in list_result.cname:
                print("证书 ID ： {}".format(c.certificate.cert_id))
                print("自定义域名： {}".format(c.domain))
                print("最后修改时间： {}".format(c.last_modified))
        return list_result.cname

    def _update_cname(self, cname_info: CnameInfo, private_key: str, certificate: str):
        create_new_cert = True
        if cname_info.certificate:
            valid_end_date = cname_info.certificate.valid_end_date
            try:
                exp_date_obj = datetime.strptime(valid_end_date, '%b %d %H:%M:%S %Y GMT')
            except (ValueError, TypeError):
                exp_date_obj = None
            if exp_date_obj is not None and exp_date_obj > datetime.utcnow():
                create_new_cert = False

        if create_new_cert:
            print(cname_info.domain+":证书已过期或未绑定证书，将创建新的证书")
            cert = oss2.models.CertInfo(certificate=certificate, private_key=private_key, force=True)
        else:
            print(cname_info.domain+":证书未过期，将更新证书")
            cert = oss2.models.CertInfo(certificate=certificate, private_key=private_key, force=True)
            #cert = oss2.models.CertInfo(cert_id=cname_info.certificate.cert_id,
            #                            certificate=certificate,
            #                            private_key=private_key,
            #                            force=True)

        input_ = oss2.models.PutBucketCnameRequest(cname_info.domain, cert)
        self.bucket.put_bucket_cname(input_)


if __name__ == '__main__':
    os.chdir(sys.path[0])

    try:
        with open("config.json", "r") as file:
            configs = json.load(file)

        for config in configs:
            access_key_id = config['Auth']['alibaba_cloud_access_key_id']
            access_key_secret = config['Auth']['alibaba_cloud_access_key_secret']

            for each in config['OSS']:
                private_key_path = each['private_key_path']
                certificate_path = each['certificate_path']

                with open(private_key_path, 'r') as f:
                    private_key_ = f.read()
                with open(certificate_path, 'r') as f:
                    certificate_ = f.read()

                target_cname_ = each['target_cname']

                o = OSS(
                    access_key_id,
                    access_key_secret,
                    each['endpoint'],
                    each['bucket_name'],
                    each['region']
                )

                o.run_update(target_cname=target_cname_, private_key=private_key_, certificate=certificate_)

    except KeyboardInterrupt:
        print("程序已被用户终止")
    except Exception as e:
        print(traceback.format_exc())
        sys.exit(1)
