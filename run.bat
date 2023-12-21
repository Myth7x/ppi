@echo off
call activate wrnet_web
call python -c "from app import create_app;from sniffer import create_sniffer;sniffer = create_sniffer();app = create_app();app.run(host='0.0.0.0', port=5000, debug=True)
```
Idk, maybe correct
```
