from dataclasses import dataclass

@dataclass(slots=True)
class SR:
    state: bool = False

    def update(self, set_: bool, reset: bool) -> bool:
        if reset:
            self.state = False
        elif set_:
            self.state = True
        return self.state