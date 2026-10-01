import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('catalog',Path(__file__).resolve().parents[1]/'scripts/catalog.py')
catalog=importlib.util.module_from_spec(spec);spec.loader.exec_module(catalog)

class CatalogTests(unittest.TestCase):
    def fixture(self, extra=None):
        manifest={'id':'dev.cartridge.test','name':'Test','description':'fixture','version':'1.0.0','author':'Test',
                  'category':'tools','permissions':['storage'],'entry':'main.lua','min_runtime':'0.6.0'}
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz') as tar:
            for name,body in [('cartridge.json',json.dumps(manifest).encode()),('main.lua',b'return {}')]:
                member=tarfile.TarInfo(name);member.size=len(body);tar.addfile(member,io.BytesIO(body))
            if extra:
                member=tarfile.TarInfo(extra);member.size=1;tar.addfile(member,io.BytesIO(b'x'))
        data=data.getvalue()
        approved={'id':manifest['id'],'version':'1.0.0','repo':'Strizzo/test-cartridge','permissions':['storage'],
                  'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        return data,approved

    def test_pinned_release_builds_expected_entry(self):
        data,app=self.fixture()
        result=catalog.build({'version':1,'apps':[app]},lambda _:data)
        self.assertEqual(result['apps'][0]['package']['min_runtime'],'0.6.0')
        self.assertEqual(result['apps'][0]['package']['sha256'],app['sha256'])

    def test_changed_bytes_identity_permissions_and_duplicate_id_fail(self):
        data,app=self.fixture()
        with self.assertRaises(ValueError):catalog.inspect_package(data+b'changed',app)
        for field,value in [('id','dev.other'),('version','2.0.0'),('permissions',['network'])]:
            with self.assertRaises(ValueError):catalog.inspect_package(data,dict(app,**{field:value}))
        with self.assertRaises(ValueError):catalog.build({'version':1,'apps':[app,app]},lambda _:data)

    def test_unsafe_and_duplicate_archive_paths_fail(self):
        for path in ['../escape','/absolute','main.lua']:
            data,app=self.fixture(path)
            with self.assertRaises(ValueError):catalog.inspect_package(data,app)

    def test_signature_covers_exact_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            key=Path(tmp)/'private.pem';pub=Path(tmp)/'public.pem'
            catalog.openssl('genpkey','-algorithm','ED25519','-out',key)
            catalog.openssl('pkey','-in',key,'-pubout','-out',pub)
            envelope=catalog.sign({'version':2,'apps':[]},key)
            self.assertEqual(catalog.verify(envelope,pub),{'version':2,'apps':[]})
            envelope['payload']+=' '
            with self.assertRaises(subprocess.CalledProcessError):catalog.verify(envelope,pub)

if __name__=='__main__':unittest.main()
