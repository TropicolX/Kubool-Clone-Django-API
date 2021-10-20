from django.urls import path
from .views import NewMessage

app_name='messaging'

urlpatterns = [
    path('<str:user_code>/',NewMessage.as_view())
]
