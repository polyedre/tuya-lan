"""Platform for sensor integration."""

from homeassistant.helpers.entity import Entity
from homeassistant.components.sensor import PLATFORM_SCHEMA
from pytuya import OutletDevice
from homeassistant.const import POWER_WATT, DEVICE_CLASS_POWER
from homeassistant.const import CONF_IP_ADDRESS, CONF_DEVICE_ID, CONF_API_KEY, CONF_SENSORS
import homeassistant.helpers.config_validation as cv
import voluptuous as vol
import logging

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

def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the sensor platform."""

    sensors = []

    for device, device_config in config[CONF_SENSORS].items():
        ip_address = device_config[CONF_IP_ADDRESS]
        local_key  = device_config[CONF_API_KEY]
        device_id  = device_config[CONF_DEVICE_ID]

        sensors.append(TuyaPlug(device_id, ip_address, local_key))

    add_entities(sensors)

class TuyaPlug(Entity):
    """Representation of a Sensor."""

    def __init__(self, device_id, ip_address, local_key):
        """Initialize the sensor."""
        self._state = None
        self.identifiants = device_id, ip_address, local_key
        self.reconnect()
        self._device_class = DEVICE_CLASS_POWER
        self.device.connection_timeout = 100
        try:
            self.data = self.device.status()
        except:
            self.data = {'dps': {'19': 0}}

    @property
    def name(self):
        """Return the name of the sensor."""
        return 'Tuya Plug'

    @property
    def state(self):
        """Return the state of the sensor."""
        return self._state

    @property
    def unit_of_measurement(self):
        """Return the unit of measurement."""
        return POWER_WATT

    def update(self):
        """Fetch new state data for the sensor.
        This is the only method that should fetch new data for Home Assistant.
        """
        try:
            self.data = self.device.status()
            _LOGGER.debug(self.data)
        except ConnectionResetError:
            self.reconnect()
            _LOGGER.info("Failed fetching data")
        finally:
            self.data = self.device.status()
        self._state = self.get_power()

    def get_power(self):
        return self.data['dps']['19'] / 10

    def reconnect(self):
        self.device = OutletDevice(*self.identifiants)
