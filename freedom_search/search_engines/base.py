from abc import ABC, abstractmethod

class SearchEngine(ABC):
    @abstractmethod
    def search(self, query, num_results=5):
        pass
