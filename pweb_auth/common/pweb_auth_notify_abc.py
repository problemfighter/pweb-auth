from abc import ABC, abstractmethod
from pweb_auth.model.operator_abc import OperatorAbc


class PWebAuthNotifyOnForgotPasswordRequest(ABC):
    @abstractmethod
    def perform(self):
        pass


class PWebAuthNotifyOnResetPasswordFailed(ABC):
    @abstractmethod
    def perform(self):
        pass


class PWebAuthNotifyOnResetPasswordSuccess(ABC):
    @abstractmethod
    def perform(self):
        pass


class PWebAuthNotifyOnLoginFailed(ABC):
    @abstractmethod
    def perform(self, operator: OperatorAbc, login_data: dict):
        pass


class PWebAuthNotifyOnLoginSuccess(ABC):
    @abstractmethod
    def perform(self, operator: OperatorAbc, login_data: dict):
        pass


class PWebAuthNotifyOnCreateOperator(ABC):
    @abstractmethod
    def perform(self):
        pass
