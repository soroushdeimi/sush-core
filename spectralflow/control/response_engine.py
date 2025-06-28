"""Automated response to detected threats."""

import time
import random
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum, auto
import logging


from .censorship_detector import ThreatEvent, ThreatLevel, CensorshipType


class ResponseAction(Enum):
    """Available response actions."""
    SWITCH_PROTOCOL = auto()
    CHANGE_PORT = auto()
    ACTIVATE_STEGANOGRAPHY = auto()
    INCREASE_OBFUSCATION = auto()
    USE_BRIDGE_RELAY = auto()
    ENABLE_TRAFFIC_MORPHING = auto()
    FALLBACK_CHANNEL = auto()
    EMERGENCY_SHUTDOWN = auto()


class ResponsePriority(Enum):
    """Priority levels for responses."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ResponseRule:
    """Defines an automated response rule."""
    threat_types: List[CensorshipType]
    min_threat_level: ThreatLevel
    actions: List[ResponseAction]
    priority: ResponsePriority
    cooldown: float = 60.0  # seconds before rule can trigger again
    confidence_threshold: float = 0.7
    last_triggered: float = 0.0


@dataclass
class ResponseContext:
    """Context information for response execution."""
    threat: ThreatEvent
    available_protocols: List[str]
    available_ports: List[int]
    current_obfuscation_level: int
    network_conditions: Dict[str, Any]


class ResponseEngine:
    """
    Automated response engine for threat mitigation.
    
    Implements rule-based responses to detected threats with adaptive
    escalation and fallback strategies.
    """
    
    def __init__(self):
        self.is_active = False
        self.response_rules: List[ResponseRule] = []
        self.response_handlers: Dict[ResponseAction, Callable] = {}
        self.response_history: List[Dict[str, Any]] = []
        
        # Response state
        self.current_obfuscation_level = 1
        self.active_protocols = ['tcp', 'udp']
        self.active_ports = [443, 80, 53]
        self.steganography_enabled = False
        self.traffic_morphing_enabled = False
        
        # Escalation state
        self.threat_escalation_count = 0
        self.last_escalation_time = 0.0
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize default rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default response rules."""
        
        # IP blocking response
        ip_blocking_rule = ResponseRule(
            threat_types=[CensorshipType.IP_BLOCKING],
            min_threat_level=ThreatLevel.MEDIUM,
            actions=[ResponseAction.USE_BRIDGE_RELAY, ResponseAction.SWITCH_PROTOCOL],
            priority=ResponsePriority.HIGH,
            cooldown=120.0,
            confidence_threshold=0.8
        )
        
        # Port blocking response
        port_blocking_rule = ResponseRule(
            threat_types=[CensorshipType.PORT_BLOCKING],
            min_threat_level=ThreatLevel.MEDIUM,
            actions=[ResponseAction.CHANGE_PORT, ResponseAction.ACTIVATE_STEGANOGRAPHY],
            priority=ResponsePriority.MEDIUM,
            cooldown=60.0,
            confidence_threshold=0.7
        )
        
        # DPI filtering response
        dpi_rule = ResponseRule(
            threat_types=[CensorshipType.DPI_FILTERING],
            min_threat_level=ThreatLevel.MEDIUM,
            actions=[ResponseAction.INCREASE_OBFUSCATION, ResponseAction.ENABLE_TRAFFIC_MORPHING],
            priority=ResponsePriority.HIGH,
            cooldown=90.0,
            confidence_threshold=0.75
        )
        
        # Traffic shaping response
        shaping_rule = ResponseRule(
            threat_types=[CensorshipType.TRAFFIC_SHAPING],
            min_threat_level=ThreatLevel.LOW,
            actions=[ResponseAction.ENABLE_TRAFFIC_MORPHING, ResponseAction.FALLBACK_CHANNEL],
            priority=ResponsePriority.MEDIUM,
            cooldown=180.0,
            confidence_threshold=0.6
        )
        
        # Connection reset response
        reset_rule = ResponseRule(
            threat_types=[CensorshipType.CONNECTION_RESET],
            min_threat_level=ThreatLevel.MEDIUM,
            actions=[ResponseAction.SWITCH_PROTOCOL, ResponseAction.INCREASE_OBFUSCATION],
            priority=ResponsePriority.HIGH,
            cooldown=45.0,
            confidence_threshold=0.8
        )
        
        # Critical threat response
        critical_rule = ResponseRule(
            threat_types=[t for t in CensorshipType],  # All types
            min_threat_level=ThreatLevel.CRITICAL,
            actions=[ResponseAction.EMERGENCY_SHUTDOWN],
            priority=ResponsePriority.CRITICAL,
            cooldown=300.0,
            confidence_threshold=0.9
        )
        
        self.response_rules.extend([
            ip_blocking_rule,
            port_blocking_rule, 
            dpi_rule,
            shaping_rule,
            reset_rule,
            critical_rule
        ])
        
        self.logger.info(f"Initialized {len(self.response_rules)} default response rules")
    
    async def start(self):
        """Start the response engine."""
        self.is_active = True
        self.logger.info("Response engine started")
    
    async def stop(self):
        """Stop the response engine."""
        self.is_active = False
        self.logger.info("Response engine stopped")
    
    async def handle_threat(self, threat: ThreatEvent, context: Optional[ResponseContext] = None):
        """Handle a detected threat event."""
        if not self.is_active:
            return
        
        self.logger.info(f"Handling threat: {threat.threat_type.name} "
                        f"(severity: {threat.severity.name}, confidence: {threat.confidence:.2f})")
        
        # Find applicable response rules
        applicable_rules = self._find_applicable_rules(threat)
        
        if not applicable_rules:
            self.logger.debug("No applicable response rules found")
            return
        
        # Sort by priority and execute
        applicable_rules.sort(key=lambda r: r.priority.value, reverse=True)
        
        for rule in applicable_rules:
            if await self._can_trigger_rule(rule, threat):
                await self._execute_rule(rule, threat, context)
                rule.last_triggered = time.time()
                break  # Execute only the highest priority rule
    
    def _find_applicable_rules(self, threat: ThreatEvent) -> List[ResponseRule]:
        """Find response rules applicable to the threat."""
        applicable = []
        
        for rule in self.response_rules:
            # Check threat type match
            if threat.threat_type not in rule.threat_types:
                continue
            
            # Check severity threshold
            if threat.severity.value < rule.min_threat_level.value:
                continue
            
            # Check confidence threshold
            if threat.confidence < rule.confidence_threshold:
                continue
            
            applicable.append(rule)
        
        return applicable
    
    async def _can_trigger_rule(self, rule: ResponseRule, threat: ThreatEvent) -> bool:
        """Check if a rule can be triggered."""
        current_time = time.time()
        
        # Check cooldown
        if current_time - rule.last_triggered < rule.cooldown:
            self.logger.debug(f"Rule on cooldown: {rule.actions}")
            return False
        
        return True
    
    async def _execute_rule(self, rule: ResponseRule, threat: ThreatEvent, context: Optional[ResponseContext]):
        """Execute a response rule."""
        self.logger.info(f"Executing response rule with actions: {[a.name for a in rule.actions]}")
        
        response_record = {
            'timestamp': time.time(),
            'threat_type': threat.threat_type.name,
            'threat_severity': threat.severity.name,
            'actions': [a.name for a in rule.actions],
            'rule_priority': rule.priority.name
        }
        
        for action in rule.actions:
            try:
                await self._execute_action(action, threat, context)
                response_record[f'{action.name}_success'] = True
            except Exception as e:
                self.logger.error(f"Failed to execute action {action.name}: {e}")
                response_record[f'{action.name}_success'] = False
                response_record[f'{action.name}_error'] = str(e)
        
        self.response_history.append(response_record)
        
        # Limit history size
        if len(self.response_history) > 1000:
            self.response_history = self.response_history[-500:]
    
    async def _execute_action(self, action: ResponseAction, threat: ThreatEvent, context: Optional[ResponseContext]):
        """Execute a specific response action."""
        
        if action == ResponseAction.SWITCH_PROTOCOL:
            await self._switch_protocol(threat, context)
        elif action == ResponseAction.CHANGE_PORT:
            await self._change_port(threat, context)
        elif action == ResponseAction.ACTIVATE_STEGANOGRAPHY:
            await self._activate_steganography(threat, context)
        elif action == ResponseAction.INCREASE_OBFUSCATION:
            await self._increase_obfuscation(threat, context)
        elif action == ResponseAction.USE_BRIDGE_RELAY:
            await self._use_bridge_relay(threat, context)
        elif action == ResponseAction.ENABLE_TRAFFIC_MORPHING:
            await self._enable_traffic_morphing(threat, context)
        elif action == ResponseAction.FALLBACK_CHANNEL:
            await self._activate_fallback_channel(threat, context)
        elif action == ResponseAction.EMERGENCY_SHUTDOWN:
            await self._emergency_shutdown(threat, context)
        else:
            self.logger.warning(f"Unknown response action: {action}")
    
    async def _switch_protocol(self, threat: ThreatEvent, context: Optional[ResponseContext]):
        """Switch to a different protocol."""
        available_protocols = ['tcp', 'udp', 'quic', 'sctp']
        
        # Remove currently active protocols
        alternatives = [p for p in available_protocols if p not in self.active_protocols]
        
        if alternatives:
            new_protocol = random.choice(alternatives)
            self.active_protocols = [new_protocol]
            self.logger.info(f"Switched to protocol: {new_protocol}")
            
            # Notify protocol hopper if handler is registered
            if ResponseAction.SWITCH_PROTOCOL in self.response_handlers:
                await self.response_handlers[ResponseAction.SWITCH_PROTOCOL](new_protocol)
    
    async def _change_port(self, threat: ThreatEvent, context: Optional[ResponseContext]):
        """Change to a different port."""
        common_ports = [80, 443, 53, 22, 25, 110, 143, 993, 995, 8080, 8443]
        blocked_port = threat.port
        
        # Select a new port different from the blocked one
        available_ports = [p for p in common_ports if p != blocked_port]
        
        if available_ports:
            new_port = random.choice(available_ports)
            self.active_ports = [new_port]
            self.logger.info(f"Changed to port: {new_port}")
            
            # Notify port manager if handler is registered
            if ResponseAction.CHANGE_PORT in self.response_handlers:
                await self.response_handlers[ResponseAction.CHANGE_PORT](new_port)
    
    async def _activate_steganography(self, threat: ThreatEvent, context: Optional[ResponseContext]):
        """Activate steganographic channels."""
        if not self.steganography_enabled:
            self.steganography_enabled = True
            self.logger.info("Activated steganographic channels")
            
            # Notify steganography system if handler is registered
            if ResponseAction.ACTIVATE_STEGANOGRAPHY in self.response_handlers:
                await self.response_handlers[ResponseAction.ACTIVATE_STEGANOGRAPHY](True)
    
    async def _increase_obfuscation(self, threat: ThreatEvent, context: Optional[ResponseContext]):
        """Increase obfuscation level."""
        if self.current_obfuscation_level < 5:  # Max level 5
            self.current_obfuscation_level += 1
            self.logger.info(f"Increased obfuscation level to: {self.current_obfuscation_level}")
            
            # Notify obfuscation system if handler is registered
            if ResponseAction.INCREASE_OBFUSCATION in self.response_handlers:
                await self.response_handlers[ResponseAction.INCREASE_OBFUSCATION](self.current_obfuscation_level)
    
    async def _use_bridge_relay(self, threat: ThreatEvent, context: Optional[ResponseContext]):
        """Switch to using bridge relays."""
        self.logger.info("Activating bridge relay mode")
        
        # Notify bridge system if handler is registered
        if ResponseAction.USE_BRIDGE_RELAY in self.response_handlers:
            await self.response_handlers[ResponseAction.USE_BRIDGE_RELAY](True)
    
    async def _enable_traffic_morphing(self, threat: ThreatEvent, context: Optional[ResponseContext]):
        """Enable traffic morphing."""
        if not self.traffic_morphing_enabled:
            self.traffic_morphing_enabled = True
            self.logger.info("Enabled traffic morphing")
            
            # Notify traffic morphing engine if handler is registered
            if ResponseAction.ENABLE_TRAFFIC_MORPHING in self.response_handlers:
                await self.response_handlers[ResponseAction.ENABLE_TRAFFIC_MORPHING](True)
    
    async def _activate_fallback_channel(self, threat: ThreatEvent, context: Optional[ResponseContext]):
        """Activate fallback communication channel."""
        self.logger.info("Activating fallback channel")
        
        # Notify fallback system if handler is registered
        if ResponseAction.FALLBACK_CHANNEL in self.response_handlers:
            await self.response_handlers[ResponseAction.FALLBACK_CHANNEL](True)
    
    async def _emergency_shutdown(self, threat: ThreatEvent, context: Optional[ResponseContext]):
        """Perform emergency shutdown."""
        self.logger.critical("Performing emergency shutdown due to critical threat")
        
        # Notify shutdown handler if registered
        if ResponseAction.EMERGENCY_SHUTDOWN in self.response_handlers:
            await self.response_handlers[ResponseAction.EMERGENCY_SHUTDOWN](threat)
        
        # Stop the response engine
        await self.stop()
    
    def register_response_handler(self, action: ResponseAction, handler: Callable):
        """Register a handler for a specific response action."""
        self.response_handlers[action] = handler
        self.logger.info(f"Registered handler for action: {action.name}")
    
    def add_response_rule(self, rule: ResponseRule):
        """Add a custom response rule."""
        self.response_rules.append(rule)
        self.logger.info(f"Added custom response rule with actions: {[a.name for a in rule.actions]}")
    
    def get_response_statistics(self) -> Dict[str, Any]:
        """Get response engine statistics."""
        if not self.response_history:
            return {
                'total_responses': 0,
                'current_state': self._get_current_state()
            }
        
        # Count responses by action type
        action_counts = {}
        successful_responses = 0
        
        for record in self.response_history:
            successful_responses += 1
            for action in record['actions']:
                action_counts[action] = action_counts.get(action, 0) + 1
        
        return {
            'total_responses': len(self.response_history),
            'successful_responses': successful_responses,
            'action_distribution': action_counts,
            'current_state': self._get_current_state(),
            'rules_count': len(self.response_rules),
            'handlers_count': len(self.response_handlers)
        }
    
    def _get_current_state(self) -> Dict[str, Any]:
        """Get current response engine state."""
        return {
            'is_active': self.is_active,
            'obfuscation_level': self.current_obfuscation_level,
            'active_protocols': self.active_protocols,
            'active_ports': self.active_ports,
            'steganography_enabled': self.steganography_enabled,
            'traffic_morphing_enabled': self.traffic_morphing_enabled,
            'threat_escalation_count': self.threat_escalation_count
        }
