# Generated by Django 3.2.8 on 2021-10-27 17:41

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('messaging', '0004_alter_message_created'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='created',
            field=models.DateTimeField(default=datetime.datetime(2021, 10, 27, 17, 41, 40, 749677, tzinfo=utc)),
        ),
    ]
