from abc import ABC, abstractmethod


class Extractor(ABC):

    @abstractmethod
    def run(self, **kwargs):
        pass


class Transformer(ABC):

    @abstractmethod
    def run(self, rows, **kwargs):
        pass


class Loader(ABC):

    @abstractmethod
    def run(self, rows, **kwargs):
        pass


class PipelineModule(ABC):

    name: str

    @abstractmethod
    def execute(self, **kwargs):
        pass