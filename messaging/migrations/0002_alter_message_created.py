# Generated by Django 3.2.8 on 2021-10-27 17:11

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('messaging', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='created',
            field=models.DateTimeField(default=datetime.datetime(2021, 10, 27, 17, 11, 3, 408558, tzinfo=utc)),
        ),
    ]
