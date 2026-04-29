compile:
	docker compose run --rm esphome compile heltec_wifi_lora_32_v2.yaml

upload:
	docker compose run --rm esphome run heltec_wifi_lora_32_v2.yaml

logs:
	docker compose run --rm esphome logs heltec_wifi_lora_32_v2.yaml

clean:
	docker compose run --rm esphome clean heltec_wifi_lora_32_v2.yaml

compile-v3:
	docker compose run --rm esphome compile heltec_wifi_lora_32_v3.yaml

upload-v3:
	docker compose run --rm esphome run heltec_wifi_lora_32_v3.yaml

logs-v3:
	docker compose run --rm esphome logs heltec_wifi_lora_32_v3.yaml

clean-v3:
	docker compose run --rm esphome clean heltec_wifi_lora_32_v3.yaml

compile-v3-monitor:
	docker compose run --rm esphome compile heltec_wifi_lora_32_v3_monitor.yaml

upload-v3-monitor:
	docker compose run --rm esphome run heltec_wifi_lora_32_v3_monitor.yaml

logs-v3-monitor:
	docker compose run --rm esphome logs heltec_wifi_lora_32_v3_monitor.yaml

clean-v3-monitor:
	docker compose run --rm esphome clean heltec_wifi_lora_32_v3_monitor.yaml

dashboard:
	docker compose up

format:
	find components tests -name '*.cpp' -o -name '*.h' -exec clang-format -i {} +

test-host:
	mkdir -p build
	c++ -std=c++17 -Wall -Wextra -Icomponents/home_io_control -Itests/host/include \
		components/home_io_control/proto_frame.cpp \
		components/home_io_control/proto_commands.cpp \
		components/home_io_control/proto_crypto.cpp \
		tests/host/protocol_smoke.cpp \
		-o build/protocol_smoke
	./build/protocol_smoke
