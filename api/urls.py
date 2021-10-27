from django.urls import path
from django.utils.translation import LANGUAGE_SESSION_KEY
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from .views import (CheckUser,
                    AllAnonMessages,
                    SignUp,
                    Login,
                    ChangePassword,
                    DeleteUser,
                    GetUser,
                    DeleteMessage,
                    BlacklistTokenView)

app_name = 'api'

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('user/messages/', AllAnonMessages.as_view(), name='all_messages'),
    path('user/message/delete/', DeleteMessage.as_view(), name='delete_message'),
    path('user/signup/', SignUp.as_view(), name="sign_up"),
    path('user/login/', Login.as_view(), name="login"),
    path('user/change_password/', ChangePassword.as_view(), name='change_password'),
    path('user/delete/', DeleteUser.as_view(), name='delete_user'),
    path('user/current_user/', GetUser.as_view(), name='get_current_user'),
    path('user/<str:share_code>/', CheckUser.as_view(), name='check_user'),
    path('user/logout/blacklist/', BlacklistTokenView.as_view(), name='blacklist'),
]
