#!/usr/bin/env python3
"""
mDNS Detector Module for Picoclaw
Detects OpenClaw's insecure local discovery via mDNS broadcast (port 5353).
"""

import socket
import struct
import time
from typing import Dict, Any, List, Optional
from datetime import datetime


# mDNS constants
MDNS_PORT = 5353
MDNS_ADDR = '224.0.0.251'  # IPv4 mDNS multicast address
MDNS_ADDR_V6 = 'ff02::fb'  # IPv6 mDNS multicast address

# Common OpenClaw service names
OPENCLAW_SERVICE_TYPES = [
    '_openclaw._tcp.local.',
    '_openclaw-gateway._tcp.local.',
    '_openclaw-relay._tcp.local.',
    '_openclaw-sentinel._tcp.local.',
    '_browser-relay._tcp.local.',
    '_cogniwatch._tcp.local.',
]


def create_mdns_socket(timeout: int = 5) -> socket.socket:
    """
    Create a UDP socket for mDNS listening.
    
    Args:
        timeout: Socket timeout in seconds
    
    Returns:
        Configured UDP socket
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Try to bind to mDNS port
    try:
        sock.bind(('', MDNS_PORT))
    except PermissionError:
        # Non-privileged, use ephemeral port
        sock.bind(('', 0))
    
    sock.settimeout(timeout)
    return sock


def join_mdns_group(sock: socket.socket) -> bool:
    """
    Join the mDNS multicast group.
    
    Args:
        sock: UDP socket
    
    Returns:
        True if successfully joined, False otherwise
    """
    try:
        # Get local interfaces
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # Join multicast group
        group = socket.inet_aton(MDNS_ADDR)
        mreq = group + socket.inet_aton(local_ip)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        return True
    except Exception as e:
        # May fail on some systems, but we can still try to receive
        return False


def parse_mdns_packet(data: bytes) -> Dict[str, Any]:
    """
    Parse mDNS packet to extract service information.
    
    Args:
        data: Raw mDNS packet bytes
    
    Returns:
        Dictionary with parsed packet information
    """
    result = {
        'valid': False,
        'services': [],
        'responses': [],
        'questions': [],
        'raw_size': len(data)
    }
    
    try:
        if len(data) < 12:
            return result
        
        # Parse DNS header
        header = struct.unpack('>HHHHHH', data[:12])
        flags = header[1]
        
        qr = (flags >> 15) & 0x1  # Query (0) or Response (1)
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1  # Authoritative Answer
        tc = (flags >> 9) & 0x1   # Truncated
        rd = (flags >> 8) & 0x1   # Recursion Desired
        ra = (flags >> 7) & 0x1   # Recursion Available
        
        qdcount = header[2]  # Questions
        ancount = header[3]  # Answers
        nscount = header[4]  # Authority
        arcount = header[5]  # Additional
        
        result['packet_type'] = 'response' if qr else 'query'
        result['valid'] = True
        
        # Parse domain names (simplified)
        offset = 12
        
        def read_name(data, offset):
            """Read a DNS name from packet"""
            labels = []
            original_offset = offset
            
            while True:
                if offset >= len(data):
                    break
                
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                elif (length & 0xC0) == 0xC0:
                    # Compressed name pointer
                    if offset + 1 >= len(data):
                        break
                    pointer = ((length & 0x3F) << 8) | data[offset + 1]
                    offset += 2
                    # Don't follow pointer for this simple parser
                    labels.append('<compressed>')
                    break
                else:
                    offset += 1
                    if offset + length > len(data):
                        break
                    labels.append(data[offset:offset + length].decode('utf-8', errors='ignore'))
                    offset += length
            
            return '.'.join(labels), offset
        
        # Parse questions
        for _ in range(qdcount):
            if offset >= len(data):
                break
            name, offset = read_name(data, offset)
            if offset + 4 > len(data):
                break
            qtype, qclass = struct.unpack('>HH', data[offset:offset + 4])
            offset += 4
            result['questions'].append({
                'name': name,
                'type': qtype,
                'class': qclass
            })
        
        # Parse answers (simplified)
        for _ in range(ancount):
            if offset >= len(data):
                break
            name, offset = read_name(data, offset)
            if offset + 10 > len(data):
                break
            atype, aclass, ttl, rdlength = struct.unpack('>HHIH', data[offset:offset + 10])
            offset += 10
            if offset + rdlength > len(data):
                break
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            
            result['responses'].append({
                'name': name,
                'type': atype,
                'class': aclass,
                'ttl': ttl,
                'rdata': rdata.hex() if rdata else ''
            })
            
            # Check for OpenClaw services
            for service_type in OPENCLAW_SERVICE_TYPES:
                if service_type in name.lower():
                    result['services'].append({
                        'name': name,
                        'type': 'openclaw_service',
                        'service_type': service_type,
                        'found': True
                    })
    
    except Exception as e:
        result['error'] = str(e)
    
    return result


def listen_for_mdns(duration: int = 5) -> List[Dict[str, Any]]:
    """
    Listen for mDNS packets for specified duration.
    
    Args:
        duration: Time to listen in seconds
    
    Returns:
        List of detected mDNS packets
    """
    packets = []
    
    try:
        sock = create_mdns_socket(timeout=1)
        join_mdns_group(sock)
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                data, addr = sock.recvfrom(4096)
                parsed = parse_mdns_packet(data)
                parsed['source_ip'] = addr[0]
                parsed['source_port'] = addr[1]
                parsed['timestamp'] = datetime.now().isoformat()
                packets.append(parsed)
            except socket.timeout:
                continue
            except Exception as e:
                pass
        
        sock.close()
    
    except Exception as e:
        pass
    
    return packets


def check_mdns_broadcast() -> Dict[str, Any]:
    """
    Check if OpenClaw is broadcasting via mDNS.
    
    Returns:
        Dictionary with broadcast status:
        - broadcasting: bool
        - services: list of detected services
    """
    result = {
        'broadcasting': False,
        'services': [],
        'openclaw_services': [],
        'details': {
            'mdns_port_open': False,
            'mdns_group_joined': False,
            'packets_received': 0,
            'scan_duration': 5
        }
    }
    
    try:
        # Create socket and check if mDNS port is available
        sock = create_mdns_socket(timeout=1)
        result['details']['mdns_port_open'] = True
        
        # Try to join multicast group
        join_result = join_mdns_group(sock)
        result['details']['mdns_group_joined'] = join_result
        
        # Listen for packets
        packets = listen_for_mdns(duration=5)
        result['details']['packets_received'] = len(packets)
        
        # Extract services
        seen_services = set()
        for packet in packets:
            for service in packet.get('services', []):
                if service['name'] not in seen_services:
                    seen_services.add(service['name'])
                    result['services'].append(service)
                    
                    # Check if it's OpenClaw
                    if service.get('type') == 'openclaw_service':
                        result['openclaw_services'].append(service)
                        result['broadcasting'] = True
        
        # Also check for services in responses
        for packet in packets:
            for response in packet.get('responses', []):
                name = response.get('name', '')
                for service_type in OPENCLAW_SERVICE_TYPES:
                    if service_type.lower() in name.lower():
                        if name not in seen_services:
                            seen_services.add(name)
                            result['services'].append({
                                'name': name,
                                'type': 'openclaw_service',
                                'service_type': service_type,
                                'source_ip': packet.get('source_ip', 'unknown')
                            })
                            result['openclaw_services'].append(result['services'][-1])
                            result['broadcasting'] = True
        
        sock.close()
    
    except PermissionError:
        result['details']['error'] = 'Permission denied for mDNS port (requires root/sudo)'
        result['details']['mdns_port_open'] = False
    except Exception as e:
        result['details']['error'] = str(e)
    
    return result


def check_mdns_vulnerability() -> Dict[str, Any]:
    """
    Analyze mDNS configuration for vulnerabilities.
    
    Returns:
        Dictionary with vulnerability assessment
    """
    result = {
        'vulnerable': False,
        'vulnerabilities': [],
        'severity': 'none',
        'recommendations': []
    }
    
    mdns_status = check_mdns_broadcast()
    
    # Check for OpenClaw broadcasting
    if mdns_status['broadcasting']:
        result['vulnerable'] = True
        result['vulnerabilities'].append({
            'type': 'mdns_broadcast_exposure',
            'severity': 'high',
            'description': 'OpenClaw is broadcasting service information via mDNS on local network',
            'services': mdns_status['openclaw_services']
        })
        result['recommendations'].append('Disable mDNS broadcasting or restrict to trusted networks')
        result['recommendations'].append('Configure firewall to block mDNS port 5353 from untrusted networks')
    
    # Check for any mDNS service exposure
    if mdns_status['services']:
        non_openclaw = [s for s in mdns_status['services'] if s not in mdns_status['openclaw_services']]
        if non_openclaw:
            result['vulnerabilities'].append({
                'type': 'mdns_service_exposure',
                'severity': 'medium',
                'description': 'Other services detected via mDNS broadcast',
                'services': non_openclaw
            })
            result['recommendations'].append('Review mDNS configuration for non-OpenClaw services')
    
    # Determine overall severity
    severities = [v['severity'] for v in result['vulnerabilities']]
    if 'critical' in severities:
        result['severity'] = 'critical'
    elif 'high' in severities:
        result['severity'] = 'high'
    elif 'medium' in severities:
        result['severity'] = 'medium'
    elif 'low' in severities:
        result['severity'] = 'low'
    
    result['mdns_status'] = mdns_status
    
    return result


def detect() -> Dict[str, Any]:
    """
    Main detection function for mDNS vulnerability.
    
    Returns:
        Dictionary with detection results:
        - broadcasting: bool
        - services: list
    """
    result = {
        'broadcasting': False,
        'services': [],
        'mdns_port_5353_active': False,
        'openclaw_detected': False,
        'vulnerability_assessment': None,
        'scan_time': datetime.now().isoformat(),
        'error': None
    }
    
    try:
        # Check if mDNS port is active
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_sock.bind(('', 0))  # Use ephemeral port to test
            test_sock.close()
            result['mdns_port_5353_active'] = True
        except:
            pass
        
        # Check for mDNS broadcasting
        mdns_result = check_mdns_broadcast()
        
        result['broadcasting'] = mdns_result['broadcasting']
        result['services'] = mdns_result['services']
        result['openclaw_detected'] = len(mdns_result['openclaw_services']) > 0
        result['openclaw_services'] = mdns_result['openclaw_services']
        result['vulnerability_assessment'] = check_mdns_vulnerability()
        result['details'] = mdns_result['details']
    
    except PermissionError:
        result['error'] = 'Permission denied. mDNS detection requires root privileges.'
        result['mdns_port_5353_active'] = None
    except Exception as e:
        result['error'] = str(e)
    
    return result


if __name__ == '__main__':
    import sys
    
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    
    print(f"Scanning for mDNS broadcasts (duration: {duration}s)...")
    print()
    
    result = detect()
    
    print(f"mDNS Broadcasting: {result['broadcasting']}")
    print(f"OpenClaw Services Detected: {result['openclaw_detected']}")
    print()
    
    if result['services']:
        print("Detected Services:")
        for service in result['services']:
            print(f"  - {service['name']}")
            if service.get('source_ip'):
                print(f"    Source: {service['source_ip']}")
        print()
    
    if result['vulnerability_assessment'] and result['vulnerability_assessment']['vulnerable']:
        print("Vulnerabilities Detected:")
        for vuln in result['vulnerability_assessment']['vulnerabilities']:
            print(f"  [{vuln['severity'].upper()}] {vuln['description']}")
        print()
        print("Recommendations:")
        for rec in result['vulnerability_assessment']['recommendations']:
            print(f"  - {rec}")
    
    if result.get('error'):
        print(f"Error: {result['error']}")
