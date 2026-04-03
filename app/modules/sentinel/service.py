from __future__ import annotations

from app.modules.sentinel.extract import SentinelExtractor
from app.modules.sentinel.transform import SentinelTransformer
from app.modules.sentinel.load import SentinelLoader


class SentinelPipeline:
    name = "sentinel"

    def __init__(self):
        self.extractor = SentinelExtractor()
        self.transformer = SentinelTransformer()
        self.loader = SentinelLoader()

    def execute(self, **kwargs):
        raw = self.extractor.run(**kwargs)
        clean = self.transformer.run(raw, **kwargs)
        loaded = self.loader.run(clean, **kwargs)

        return {
            "module": self.name,
            "extracted": len(raw),
            "transformed": len(clean),
            "loaded": loaded,
        }


def run_sentinel_pipeline(**kwargs):
    pipeline = SentinelPipeline()
    return pipeline.execute(**kwargs)