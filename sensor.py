"""Platform for sensor integration."""

from homeassistant.helpers.entity import Entity
from homeassistant.components.sensor import PLATFORM_SCHEMA
from pytuya import OutletDevice
from homeassistant.const import POWER_WATT, DEVICE_CLASS_POWER
from homeassistant.const import CONF_IP_ADDRESS, CONF_DEVICE_ID, CONF_API_KEY, CONF_SENSORS
import homeassistant.helpers.config_validation as cv
import voluptuous as vol
import logging
import csv
import os
# import listen_devices as l
import asyncio as aio

SENSORS_FILE = os.environ['HOME'] + "/.homeassistant/custom_components/tuya_lan/.sensors.txt"
_LOGGER = logging.getLogger(__name__)

# Validation of the user's configuration
SENSOR_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_IP_ADDRESS): cv.string,
    vol.Required(CONF_DEVICE_ID): cv.string,
    vol.Required(CONF_API_KEY): cv.string,
})

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {vol.Required(CONF_SENSORS): cv.schema_with_slug_keys(SENSOR_SCHEMA)}
)

# l.start_background_process()

def setup_platform(hass, config, add_entities,
                               discovery_info=None):
    """Set up the sensor platform."""

    sensors = []
    _LOGGER.debug("Setuping Tuya Sensors")

    loaded_sensors = load_registered_sensors()
    new_sensors = [s for s in loaded_sensors if not s in sensors]

    _LOGGER.debug(new_sensors)
    new_sensors_entities = [TuyaPlug(*s) for s in new_sensors]
    add_entities(new_sensors_entities)

    # def handler_add_sensor():
    #     _LOGGER.debug("Event Handled")
    #     loaded_sensors = load_registered_sensors()
    #     new_sensors = [s for s in loaded_sensors if not s in sensors]

    #     new_sensors_entities = [TuyaPlug(*s) for s in new_sensors]
    #     add_entities(new_sensors_entities)

def load_registered_sensors():
    sensors = []
    with open(SENSORS_FILE, 'r') as sensor_file:
        data = csv.reader(sensor_file)
        for ip_address, device_id, local_key in data:
            sensors.append((ip_address, device_id, local_key))
    return sensors

class TuyaPlug(Entity):
    """Representation of a Tuya plug sensor."""

    number_of_plug = 0

    def __init__(self, ip_address, device_id, local_key):
        """Initialize the sensor."""
        _LOGGER.debug("Creating Plug(ip=%s, id=%s, key=%s)", ip_address, device_id, local_key)
        self.error_state = 'Not detected'
        self._power = self.error_state
        self._voltage = self.error_state
        self._intensity = self.error_state
        self._state = self.error_state
        self.identifiants = device_id, ip_address, local_key
        self.data = {}
        self.reconnect()
        self._device_class = DEVICE_CLASS_POWER
        TuyaPlug.number_of_plug += 1

    @property
    def name(self):
        """Return the name of the sensor."""
        return 'Tuya Plug {}'.format(TuyaPlug.number_of_plug)

    @property
    def unit_of_measurement(self):
        """Return the unit of measurement."""
        return POWER_WATT

    @property
    def state(self):
        """Return the default state of the plug."""
        return self._power

    @property
    def power(self):
        """Return the power of the plug."""
        return self._power

    @property
    def voltage(self):
        """Return the voltage of the plug."""
        return self._voltage

    @property
    def intensity(self):
        """Return the intensity of the plug."""
        return self._intensity

    def update(self):
        """Fetch new state data for the plug """
        self.data = {}
        for _ in range(3):
            try:
                self.data = self.device.status()
                _LOGGER.debug(self.data)
                break
            except ConnectionResetError:
                _LOGGER.info("Failed fetching data, reconnecting...")
                self.reconnect()
        if self.data:
            _LOGGER.debug("New data fetched : ", self.data)
            self._power = self.get_power()
            self._voltage = self.get_voltage()
            self._intensity = self.get_intensity()
        else:
            self._power = self.error_state

    def get_intensity(self):
        """Return the intensity in mA"""
        return self.data['dps']['18'] / 10

    def get_power(self):
        """Return the power in Watts"""
        return self.data['dps']['19'] / 10

    def get_voltage(self):
        """Return the voltage in V"""
        return self.data['dps']['20'] / 10

    def reconnect(self):
        """Reconnects to the Device"""
        self.device = OutletDevice(*self.identifiants)
