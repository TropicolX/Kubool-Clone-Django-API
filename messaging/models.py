from django.db import models
from django.utils import timezone
from datetime import timedelta

currentTime = timezone.now()


class Message(models.Model):
    content = models.TextField()
    created = models.DateTimeField(default=timezone.now)

    class Meta():
        ordering = ("-created",)

    def clearTime(self):
        deadline = self.created + timedelta(hours=23)
        return currentTime > deadline
