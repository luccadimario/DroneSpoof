# config.py
DRONE_TYPES = {
    'ASTM_F3411': {
        'header': b'\x0d\x5d\xf0\x19\x04',
        'message_types': {
            'basic_id': 0x00,
            'location': 0x10,
            'system': 0x40
        }
    },
    'DJI': {
        'header': b'DJI\x00',
        'message_types': {
            'basic_id': 0x10,
            'location': 0x20
        }
    }
}

MONITORING_CONFIG = {
    'interface': 'wlan0',
    'log_level': 'INFO',
    'save_packets': True,
    'packet_buffer': 1000
}

