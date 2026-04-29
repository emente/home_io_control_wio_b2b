import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import light
from esphome.const import CONF_OUTPUT_ID

from . import home_io_control_ns, IOHomeControlComponent, CONF_HOME_IO_CONTROL_ID, validate_device_id

DEPENDENCIES = ["home_io_control"]

CONF_DEVICE_ID = "io_device_id"

IOHomeLight = home_io_control_ns.class_("IOHomeLight", light.LightOutput, cg.Component)

CONFIG_SCHEMA = (
    # Expose this as a binary light on purpose. The transport may carry 0-100 values, but only
    # on/off semantics are backed by current protocol evidence, needs real device to verify
    light.light_schema(IOHomeLight, light.LightType.BINARY)
    .extend(
        {
            cv.GenerateID(CONF_HOME_IO_CONTROL_ID): cv.use_id(
                IOHomeControlComponent
            ),
            cv.Required(CONF_DEVICE_ID): validate_device_id,
        }
    )
    .extend(cv.COMPONENT_SCHEMA)
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_OUTPUT_ID])
    await cg.register_component(var, config)
    await light.register_light(var, config)

    parent = await cg.get_variable(config[CONF_HOME_IO_CONTROL_ID])
    cg.add(var.set_parent(parent))
    cg.add(var.set_device_id(config[CONF_DEVICE_ID]))