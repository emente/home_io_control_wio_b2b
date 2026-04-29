import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import cover
from esphome.const import CONF_ID

from . import home_io_control_ns, IOHomeControlComponent, CONF_HOME_IO_CONTROL_ID, validate_device_id

DEPENDENCIES = ["home_io_control"]

CONF_DEVICE_ID = "io_device_id"
CONF_INVERT_POSITION = "invert_position"

IOHomeCover = home_io_control_ns.class_("IOHomeCover", cover.Cover, cg.Component)

CONFIG_SCHEMA = (
    cover.cover_schema(IOHomeCover)
    .extend(
        {
            cv.GenerateID(CONF_HOME_IO_CONTROL_ID): cv.use_id(
                IOHomeControlComponent
            ),
            cv.Required(CONF_DEVICE_ID): validate_device_id,
            cv.Optional(CONF_INVERT_POSITION, default=False): cv.boolean,
        }
    )
    .extend(cv.COMPONENT_SCHEMA)
)


async def to_code(config):
    var = await cover.new_cover(config)
    await cg.register_component(var, config)

    parent = await cg.get_variable(config[CONF_HOME_IO_CONTROL_ID])
    cg.add(var.set_parent(parent))
    cg.add(var.set_device_id(config[CONF_DEVICE_ID]))
    cg.add(var.set_invert_position(config[CONF_INVERT_POSITION]))
