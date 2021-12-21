# at w3gym/backend/bases/models.py
import uuid

# from django.core.validators import MinValueValidator
from django.conf import settings
from django.core.validators import MinValueValidator
from django.db import models


class BaseModel(models.Model):
    """Define all common fields for all table."""

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )  # generate unique id.
    created_on = models.DateTimeField(
        auto_now_add=True
    )  # object creation time. will automatic generate
    updated_on = models.DateTimeField(
        auto_now=True
    )  # object update time. will automatic generate

    class Meta:
        abstract = True  # define this table/model is abstract.


class BaseModelWithOutId(models.Model):
    """Base Model with out id"""

    created_on = models.DateTimeField(
        auto_now_add=True
    )  # object creation time. will automatic generate
    updated_on = models.DateTimeField(
        auto_now=True
    )  # object update time. will automatic generate

    class Meta:
        abstract = True  # define this table/model is abstract.


class CheckInCheckOut(models.Model):
    """Base Model with check in and check out time"""

    check_in = models.DateTimeField(
        auto_now_add=True
    )  # object check-in time. will automatic generate
    check_out = models.DateTimeField(
        blank=True, null=True
    )

    class Meta:
        abstract = True  # define this table/model is abstract.


class BaseIdentification(models.Model):
    RFID_card = models.CharField(max_length=64, blank=True, null=True)
    biometric_id = models.CharField(max_length=64, blank=True, null=True)

    class Meta:
        abstract = True  # define this table/model is abstract.


class BaseBodyMeasurement(BaseModelWithOutId):
    weight = models.FloatField()  # will measure in kilogram
    height = models.FloatField(blank=True, null=True)  # will measure in centi-metre
    chest = models.FloatField(blank=True, null=True)  # will measure in centi-metre
    neck = models.FloatField(blank=True, null=True)  # will measure in centi-metre
    left_arm = models.FloatField(blank=True, null=True)  # will measure in centi-metre
    right_arm = models.FloatField(blank=True, null=True)  # will measure in centi-metre
    waist = models.FloatField(blank=True, null=True)  # will measure in centi-metre
    hips = models.FloatField(blank=True, null=True)  # will measure in centi-metre
    left_thigh = models.FloatField(blank=True, null=True)  # will measure in centi-metre
    right_thigh = models.FloatField(blank=True, null=True)  # will measure in centi-metre
    left_calf = models.FloatField(blank=True, null=True)  # will measure in centi-metre
    right_calf = models.FloatField(blank=True, null=True)  # will measure in centi-metre

    class Meta:
        abstract = True  # define this table/model is abstract.


class BasePriceModel(BaseModelWithOutId):
    actual_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
    )
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        help_text="price after discount",
        blank=True
    )
    discount_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        blank=True,
        null=True
    )
    vat_percent = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        blank=True,
        null=True
    )
    price_with_vat = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        help_text="price adding vat & discount",
        blank=True,
        null=True
    )

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        price_after_discount = self.actual_price - ((self.discount_percent * self.actual_price) / 100)
        self.price = price_after_discount
        self.vat_percent = settings.VAT_PERCENT
        self.price_with_vat = price_after_discount + ((self.vat_percent * price_after_discount) / 100)
        super(BasePriceModel, self).save(*args, **kwargs)
