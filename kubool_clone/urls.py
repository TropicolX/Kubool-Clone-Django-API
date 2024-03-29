from django.contrib import admin
from django.urls import path, include
from django.views.generic.base import TemplateView

from rest_framework import permissions
# from rest_framework.schemas import get_schema_view
# from rest_framework.documentation import include_docs_urls
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


schema_view = get_schema_view(
    openapi.Info(
        title="Kubool Clone API",
        default_version='v1',
        description="Kubool is an anonymous messaging platform that allows you to give honest feedback and compliments.",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@snippets.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls', namespace='api')),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('swagger/', schema_view.with_ui('swagger',
         cache_timeout=0), name='schema-swagger-ui'),
    path('swagger/api.json', schema_view.without_ui(cache_timeout=0),
         name='documentation'),
    path('redoc/', schema_view.with_ui('redoc',
         cache_timeout=0), name='schema-redoc'),
    path('messaging/', include('messaging.urls', namespace='messaging')),
    path('', TemplateView.as_view(template_name='index.html')),
    # path('docs/', include_docs_urls(title='Kubool Clone API')),
    # path('schema', get_schema_view(
    #     title="Kubool Clone API",
    #     version='1.0.0',
    #     description="Kubool is an anonymous messaging platform that allows you to give honest feedback and compliments.",
    # ), name="openapi-schema"),
]
