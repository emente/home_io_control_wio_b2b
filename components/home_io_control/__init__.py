import esphome.codegen as cg
import esphome.config_validation as cv
from esphome import pins
from esphome.components import spi
from esphome.const import CONF_ID

DEPENDENCIES = ["spi"]
AUTO_LOAD = ["button", "cover", "light", "switch"]
MULTI_CONF = False

CONF_HOME_IO_CONTROL_ID = "home_io_control_id"
CONF_RST_PIN = "rst_pin"
CONF_DIO0_PIN = "dio0_pin"
CONF_DIO4_PIN = "dio4_pin"
CONF_DIO1_PIN = "dio1_pin"
CONF_BUSY_PIN = "busy_pin"
CONF_NODE_ID = "node_id"
CONF_SYSTEM_KEY = "system_key"
CONF_TX_POWER = "tx_power"
CONF_PA_PIN = "pa_pin"
CONF_RADIO_TYPE = "radio_type"
CONF_FEM_EN_PIN = "fem_en_pin"
CONF_VFEM_PIN = "vfem_pin"
CONF_FEM_PA_PIN = "fem_pa_pin"
CONF_TCXO_VOLTAGE = "tcxo_voltage"

home_io_control_ns = cg.esphome_ns.namespace("home_io_control")
IOHomeControlComponent = home_io_control_ns.class_(
    "IOHomeControlComponent", cg.Component, spi.SPIDevice
)

PA_PIN_OPTIONS = {
    "BOOST": 0x80,
    "RFO": 0x00,
}

RADIO_TYPE_OPTIONS = {
    "sx1276": "sx1276",
    "sx1262": "sx1262",
}

TCXO_VOLTAGE_OPTIONS = {
    "1_6V": 0x01,
    "1_7V": 0x02,
    "1_8V": 0x03,
    "2_2V": 0x04,
    "2_4V": 0x05,
    "2_7V": 0x06,
    "3_0V": 0x07,
    "3_3V": 0x08,
}


def validate_node_id(value):
    value = cv.string_strict(value).upper()
    if len(value) != 6:
        raise cv.Invalid("Node ID must be exactly 6 hex characters (3 bytes)")
    try:
        int(value, 16)
    except ValueError:
        raise cv.Invalid("Node ID must be valid hexadecimal")
    return value


def validate_system_key(value):
    value = cv.string_strict(value).upper()
    if len(value) != 32:
        raise cv.Invalid("System key must be exactly 32 hex characters (16 bytes)")
    try:
        int(value, 16)
    except ValueError:
        raise cv.Invalid("System key must be valid hexadecimal")
    return value


def validate_device_id(value):
    value = cv.string_strict(value).upper()
    if len(value) != 6:
        raise cv.Invalid("Device ID must be exactly 6 hex characters (3 bytes)")
    try:
        int(value, 16)
    except ValueError:
        raise cv.Invalid("Device ID must be valid hexadecimal")
    return value


CONFIG_SCHEMA = (
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(IOHomeControlComponent),
            cv.Required(CONF_RST_PIN): pins.internal_gpio_output_pin_schema,
            cv.Optional(CONF_DIO0_PIN): pins.internal_gpio_input_pin_schema,
            cv.Optional(CONF_DIO4_PIN): pins.internal_gpio_input_pin_schema,
            cv.Optional(CONF_DIO1_PIN): pins.internal_gpio_input_pin_schema,
            cv.Optional(CONF_BUSY_PIN): pins.internal_gpio_input_pin_schema,
            cv.Required(CONF_NODE_ID): validate_node_id,
            cv.Required(CONF_SYSTEM_KEY): validate_system_key,
            cv.Optional(CONF_TX_POWER, default=17): cv.int_range(min=0, max=22),
            cv.Optional(CONF_PA_PIN, default="BOOST"): cv.enum(
                PA_PIN_OPTIONS, upper=True
            ),
            cv.Optional(CONF_RADIO_TYPE): cv.enum(RADIO_TYPE_OPTIONS, lower=True),
            cv.Optional(CONF_FEM_EN_PIN): pins.internal_gpio_output_pin_schema,
            cv.Optional(CONF_VFEM_PIN): pins.internal_gpio_output_pin_schema,
            cv.Optional(CONF_FEM_PA_PIN): pins.internal_gpio_output_pin_schema,
            cv.Optional(CONF_TCXO_VOLTAGE, default="1_8V"): cv.enum(
                TCXO_VOLTAGE_OPTIONS, upper=True
            ),
        }
    )
    .extend(cv.COMPONENT_SCHEMA)
    .extend(spi.spi_device_schema(True, 8e6, "mode0"))
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await spi.register_spi_device(var, config)

    rst_pin = await cg.gpio_pin_expression(config[CONF_RST_PIN])
    cg.add(var.set_rst_pin(rst_pin))

    if CONF_DIO0_PIN in config:
        dio0_pin = await cg.gpio_pin_expression(config[CONF_DIO0_PIN])
        cg.add(var.set_dio0_pin(dio0_pin))

    if CONF_DIO4_PIN in config:
        dio4_pin = await cg.gpio_pin_expression(config[CONF_DIO4_PIN])
        cg.add(var.set_dio4_pin(dio4_pin))

    if CONF_DIO1_PIN in config:
        dio1_pin = await cg.gpio_pin_expression(config[CONF_DIO1_PIN])
        cg.add(var.set_dio1_pin(dio1_pin))

    if CONF_BUSY_PIN in config:
        busy_pin = await cg.gpio_pin_expression(config[CONF_BUSY_PIN])
        cg.add(var.set_busy_pin(busy_pin))

    if CONF_FEM_EN_PIN in config:
        fem_en_pin = await cg.gpio_pin_expression(config[CONF_FEM_EN_PIN])
        cg.add(var.set_fem_en_pin(fem_en_pin))

    if CONF_VFEM_PIN in config:
        vfem_pin = await cg.gpio_pin_expression(config[CONF_VFEM_PIN])
        cg.add(var.set_vfem_pin(vfem_pin))

    if CONF_FEM_PA_PIN in config:
        fem_pa_pin = await cg.gpio_pin_expression(config[CONF_FEM_PA_PIN])
        cg.add(var.set_fem_pa_pin(fem_pa_pin))

    cg.add(var.set_node_id(config[CONF_NODE_ID]))
    cg.add(var.set_system_key(config[CONF_SYSTEM_KEY]))
    cg.add(var.set_tx_power(config[CONF_TX_POWER]))
    cg.add(var.set_pa_pin(config[CONF_PA_PIN]))

    if CONF_RADIO_TYPE in config:
        cg.add(var.set_radio_type(config[CONF_RADIO_TYPE]))

    cg.add(var.set_tcxo_voltage(config[CONF_TCXO_VOLTAGE]))
