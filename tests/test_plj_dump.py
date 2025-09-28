"""Test plj_dump.py against various plj files"""

import json

import pytest
from clirunner import CliRunner

from plj_dump import main

TEST_DIR = "tests/data"
TEST_FILES = [
    "Album-change.plj",
    "Album-snapshot.plj",
    "Asset-change.plj",
    "Asset-snapshot.plj",
    "DeferredRebuildFace-snapshot.plj",
    "DetectedFace-change.plj",
    "DetectedFace-snapshot.plj",
    "FetchingAlbum-snapshot.plj",
    "FileSystemVolume-snapshot.plj",
    "Folder-change.plj",
    "Folder-snapshot.plj",
    "ImportSession-change.plj",
    "ImportSession-snapshot.plj",
    "Keyword-change.plj",
    "Keyword-snapshot.plj",
    "Memory-snapshot.plj",
    "MigrationHistory-change.plj",
    "MigrationHistory-snapshot.plj",
    "Person-change.plj",
    "Person-snapshot.plj",
    "ProjectAlbum-snapshot.plj",
    "SocialGroup-change.plj",
]


@pytest.mark.parametrize("test_file", TEST_FILES)
def test_dump(test_file):
    runner = CliRunner()
    result = runner.invoke(main, [TEST_DIR + "/" + test_file])
    assert result.exit_code == 0


def test_dump_album_head():
    runner = CliRunner()
    result = runner.invoke(main, [TEST_DIR + "/Album-snapshot.plj", "--head", "1"])
    assert result.exit_code == 0
    results = json.loads(result.output)
    assert len(results) == 1
    assert sorted(results["entries"][0]["attributes"]["assets_decoded"]) == sorted(
        [
            "1EB2B765-0765-43BA-A90C-0D0580E6172C",
            "F12384F6-CD17-4151-ACBA-AE0E3688539E",
            "D79B8D77-BFFC-460B-9312-034F2877D35B",
        ]
    )
