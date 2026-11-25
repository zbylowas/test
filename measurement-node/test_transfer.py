import os
import unittest
from importlib import import_module
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

node = import_module("measurement-node.transfer")


class NodeTests(unittest.TestCase):
    def setUp(self):
        node.active = None
        key = "test-only-" * 5
        env = patch.dict(os.environ, VIPNET_NODE_TOKEN=key, VIPNET_TRANSFER_BYTES="65536",
                         VIPNET_TRANSFER_BPS="1048576", VIPNET_TRANSFER_SECONDS="20")
        env.start()
        self.addCleanup(env.stop)
        self.client = TestClient(node.app)
        self.addCleanup(self.client.close)
        self.path = "/measure/v1/runs/" + str(uuid4())
        self.master = {"Authorization": "Bearer " + key}
        self.assertEqual(self.client.post(self.path).status_code, 403)
        reserve = self.client.post(self.path, headers=self.master)
        self.assertEqual(reserve.status_code, 201)
        self.ticket = {"Authorization": "Bearer " + reserve.json()["ticket"]}

    def test_scope_limits_counts_and_replay(self):
        self.assertEqual(self.client.post(self.path, headers=self.master).status_code, 429)
        self.assertEqual(self.client.get(self.path + "/download", headers=self.master).status_code, 403)
        self.assertEqual(self.client.head("/measure/v1/runs/" + str(uuid4()) + "/latency",
                                          headers=self.ticket).status_code, 403)
        self.assertEqual(self.client.post(self.path + "/upload", content=b"short", headers=self.ticket).status_code, 413)
        data = self.client.get(self.path + "/download", headers=self.ticket)
        self.assertEqual(len(data.content), 65536)
        self.assertEqual(self.client.get(self.path + "/download", headers=self.ticket).status_code, 409)
        post = self.client.post(self.path + "/upload", content=data.content, headers=self.ticket)
        self.assertEqual(post.json()["bytes"], 65536)
        report = self.client.get(self.path + "/status", headers=self.ticket).json()
        for side in ("upload", "download"):
            self.assertTrue(report[side]["complete"])
            self.assertEqual(report[side]["bytes"], 65536)
            self.assertGreaterEqual(report[side]["duration_ms"], 490)
        self.assertEqual(self.client.post(self.path + "/finish", headers=self.ticket).status_code, 204)
        self.assertEqual(self.client.get(self.path + "/status", headers=self.ticket).status_code, 403)

    def test_windowed_batch(self):
        from uuid import UUID
        node.active = None
        with patch.dict(os.environ, VIPNET_CAPACITY_BPS="1000000000"):
            offer = node.start_run(UUID(self.path.split("/")[-1]), capacity=True)
        self.assertEqual(offer["profile"]["mode"], "windowed")
        h = {"Authorization": "Bearer " + offer["ticket"]}
        get = lambda i: self.client.get(f"{self.path}/blocks/download/{i}?n=65536", headers=h)
        commit = self.path + "/commit/download"
        self.assertEqual(self.client.get(self.path + "/blocks/download/1?n=65536",headers=self.ticket).status_code,403)
        self.assertEqual(self.client.get(self.path + "/download",headers=h).status_code,409)
        self.assertEqual(get(8192).status_code,422)
        self.assertEqual(len(get(1).content),65536)
        self.assertEqual(get(1).status_code,409)
        self.assertEqual(self.client.post(commit,headers=h).status_code,409)
        self.assertEqual(get(0).status_code,200)
        self.assertEqual(self.client.post(commit,headers=h).json()["bytes"],131072)
        self.assertEqual(get(2).status_code,409)
        upload = self.path + "/blocks/upload/0?n=65536"
        self.assertEqual(self.client.post(upload,headers=h,content=b"x").status_code,413)
        self.assertEqual(self.client.post(upload,headers=h,content=bytes(65536)).status_code,204)
        self.assertEqual(self.client.post(self.path+"/commit/upload",headers=h).json()["bytes"],65536)
        self.assertEqual(self.client.post(self.path+"/finish",headers=h).status_code,204)

    def test_expired_ticket(self):
        node.active.started -= 30
        self.assertEqual(self.client.head(self.path + "/latency", headers=self.ticket).status_code, 410)
        other = "/measure/v1/runs/" + str(uuid4())
        self.assertEqual(self.client.post(other, headers=self.master).status_code, 201)
