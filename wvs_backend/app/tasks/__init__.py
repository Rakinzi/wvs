"""Celery task package.

Task modules are imported explicitly by Celery configuration. Keeping package
initialization empty avoids importing task decorators before Celery is
initialized.
"""
