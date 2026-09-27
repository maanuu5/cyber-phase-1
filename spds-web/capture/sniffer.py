import threading
import time
from scapy.all import get_if_list, conf, sniff
from detection.features import extract_features
from detection.rules import RuleEngine
from storage.db import insert_alert

class LiveSniffer:
    """
    Manages background packet capture on a specified network interface using Scapy.
    """
    def __init__(self):
        self.thread = None
        self.is_running = False
        self.interface = None
        self.stop_event = threading.Event()
        self.rule_engine = RuleEngine()
        self.packet_count = 0
        self.alert_count = 0
        self.error_message = None
        self.db_path = None

    def get_interfaces(self):
        """Returns a list of available network interface dictionaries."""
        interfaces = []
        try:
            # Try Scapy's conf.ifaces first for detailed descriptions
            if hasattr(conf, 'ifaces') and conf.ifaces:
                for iface in conf.ifaces.values():
                    name = getattr(iface, 'name', str(iface))
                    description = getattr(iface, 'description', name)
                    dev_name = getattr(iface, 'devname', name)
                    interfaces.append({
                        'id': dev_name,
                        'name': description or name,
                        'devname': dev_name
                    })
        except Exception:
            pass

        # Fallback to get_if_list() if empty or failed
        if not interfaces:
            raw_list = get_if_list()
            for item in raw_list:
                interfaces.append({
                    'id': item,
                    'name': item,
                    'devname': item
                })
        return interfaces

    def start_sniffing(self, interface_name, db_path=None):
        """Starts sniffing in a background thread on the specified interface."""
        if self.is_running:
            return {'success': False, 'error': 'Capture is already running'}

        self.interface = interface_name
        self.db_path = db_path
        self.is_running = True
        self.stop_event.clear()
        self.rule_engine.reset_state()
        self.packet_count = 0
        self.alert_count = 0
        self.error_message = None

        self.thread = threading.Thread(target=self._sniff_worker, daemon=True)
        self.thread.start()
        return {
            'success': True,
            'message': f'Capture started on interface {interface_name}',
            'interface': interface_name
        }

    def _sniff_worker(self):
        """Worker thread executing scapy.sniff."""
        def packet_callback(packet):
            self.packet_count += 1
            feats = extract_features(packet)
            if feats is not None:
                alerts = self.rule_engine.analyze(feats)
                for alert in alerts:
                    insert_alert(alert, db_path=self.db_path)
                    self.alert_count += 1

        def stop_check(packet):
            return self.stop_event.is_set()

        try:
            # Sniff packets until stop_event is set
            sniff(
                iface=self.interface if self.interface != 'default' else None,
                prn=packet_callback,
                stop_filter=stop_check,
                store=False
            )
        except Exception as e:
            self.error_message = str(e)
        finally:
            self.is_running = False

    def stop_sniffing(self):
        """Stops the background sniffing thread."""
        if not self.is_running and (not self.thread or not self.thread.is_alive()):
            return {'success': False, 'error': 'Capture is not running'}

        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3.0)

        self.is_running = False
        return {
            'success': True,
            'message': 'Capture stopped',
            'packet_count': self.packet_count,
            'alert_count': self.alert_count
        }

    def get_status(self):
        """Returns the current sniffer status."""
        return {
            'is_running': self.is_running,
            'interface': self.interface,
            'packet_count': self.packet_count,
            'alert_count': self.alert_count,
            'error': self.error_message
        }

# Global singleton sniffer instance
sniffer = LiveSniffer()
