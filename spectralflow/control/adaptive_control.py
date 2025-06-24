"""Adaptive control loop with ML-based threat response."""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
import statistics
from collections import deque

from .censorship_detector import CensorshipDetector, ThreatLevel, CensorshipType
from .threat_monitor import ThreatMonitor
from .response_engine import ResponseEngine
from ..core.quantum_obfuscator import QuantumObfuscator
from ..transport.adaptive_transport import AdaptiveTransport
from ..network.mirror_network import MirrorNetwork


# Condition evaluation system
class ConditionEvaluator(ABC):
    """Base class for condition evaluation."""
    
    @abstractmethod
    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate the condition given the current context."""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """Get human-readable description of the condition."""
        pass


class ThreatLevelCondition(ConditionEvaluator):
    """Evaluates threat level conditions."""
    
    def __init__(self, operator: str, threshold: ThreatLevel):
        self.operator = operator
        self.threshold = threshold
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        current_level = context.get('threat_level', ThreatLevel.NONE)
        
        if self.operator == '>=':
            return current_level.value >= self.threshold.value
        elif self.operator == '==':
            return current_level == self.threshold
        elif self.operator == '>':
            return current_level.value > self.threshold.value
        elif self.operator == '<=':
            return current_level.value <= self.threshold.value
        elif self.operator == '<':
            return current_level.value < self.threshold.value
        
        return False
    
    def get_description(self) -> str:
        return f"threat_level {self.operator} {self.threshold.name}"


class CensorshipTypeCondition(ConditionEvaluator):
    """Evaluates censorship type detection conditions."""
    
    def __init__(self, censorship_type: CensorshipType):
        self.censorship_type = censorship_type
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        detected_types = context.get('detected_censorship', [])
        return self.censorship_type in detected_types
    
    def get_description(self) -> str:
        return f"censorship_type == {self.censorship_type.name}"


class PerformanceCondition(ConditionEvaluator):
    """Evaluates performance metric conditions."""
    
    def __init__(self, metric: str, operator: str, threshold: float):
        self.metric = metric
        self.operator = operator
        self.threshold = threshold
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        metrics = context.get('current_metrics')
        if not metrics:
            return False
        
        value = getattr(metrics, self.metric, None)
        if value is None:
            return False
        
        if self.operator == '<':
            return value < self.threshold
        elif self.operator == '<=':
            return value <= self.threshold
        elif self.operator == '>':
            return value > self.threshold
        elif self.operator == '>=':
            return value >= self.threshold
        elif self.operator == '==':
            return abs(value - self.threshold) < 1e-6
        
        return False
    
    def get_description(self) -> str:
        return f"{self.metric} {self.operator} {self.threshold}"


class StabilityCondition(ConditionEvaluator):
    """Evaluates connection stability conditions."""
    
    def __init__(self, operator: str, duration: float):
        self.operator = operator
        self.duration = duration
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        stability_duration = context.get('stability_duration', 0.0)
        
        if self.operator == '>':
            return stability_duration > self.duration
        elif self.operator == '>=':
            return stability_duration >= self.duration
        elif self.operator == '<':
            return stability_duration < self.duration
        elif self.operator == '<=':
            return stability_duration <= self.duration
        
        return False
    
    def get_description(self) -> str:
        return f"stable_for {self.operator} {self.duration}s"


class CompoundCondition(ConditionEvaluator):
    """Evaluates compound conditions using AND/OR logic."""
    
    def __init__(self, left: ConditionEvaluator, operator: str, right: ConditionEvaluator):
        self.left = left
        self.operator = operator.upper()
        self.right = right
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        left_result = self.left.evaluate(context)
        right_result = self.right.evaluate(context)
        
        if self.operator == 'AND':
            return left_result and right_result
        elif self.operator == 'OR':
            return left_result or right_result
        
        return False
    
    def get_description(self) -> str:
        return f"({self.left.get_description()}) {self.operator} ({self.right.get_description()})"


class ConditionFactory:
    """
    Factory for creating condition evaluators from configuration.
    
    Provides a clean interface for creating complex condition evaluators
    from simple configuration objects or strings.
    """
    
    @staticmethod
    def create_from_dict(config: Dict[str, Any]) -> ConditionEvaluator:
        """Create a condition evaluator from a configuration dictionary."""
        condition_type = config.get('type')
        
        if condition_type == 'threat_level':
            return ThreatLevelCondition(
                operator=config['operator'],
                threshold=ThreatLevel[config['threshold']]
            )
        elif condition_type == 'censorship_type':
            return CensorshipTypeCondition(
                censorship_type=CensorshipType[config['censorship_type']]
            )
        elif condition_type == 'performance':
            return PerformanceCondition(
                metric=config['metric'],
                operator=config['operator'],
                threshold=config['threshold']
            )
        elif condition_type == 'stability':
            return StabilityCondition(
                operator=config['operator'],
                duration=config['duration']
            )
        elif condition_type == 'compound':
            left = ConditionFactory.create_from_dict(config['left'])
            right = ConditionFactory.create_from_dict(config['right'])
            return CompoundCondition(left, config['operator'], right)
        
        raise ValueError(f"Unknown condition type: {condition_type}")
    
    @staticmethod
    def create_from_string(condition_str: str) -> ConditionEvaluator:
        """Create a condition evaluator from a string (legacy support)."""
        # Simple parser for common patterns
        condition_str = condition_str.strip()
        
        if "threat_level >= HIGH" in condition_str:
            return ThreatLevelCondition('>=', ThreatLevel.HIGH)
        elif "threat_level == NONE" in condition_str:
            return ThreatLevelCondition('==', ThreatLevel.NONE)
        elif "censorship_type == DPI_FILTERING" in condition_str:
            return CensorshipTypeCondition(CensorshipType.DPI_FILTERING)
        elif "censorship_type == IP_BLOCKING" in condition_str:
            return CensorshipTypeCondition(CensorshipType.IP_BLOCKING)
        elif "success_rate < 0.8" in condition_str:
            return PerformanceCondition('success_rate', '<', 0.8)
        elif "stable_for > 300" in condition_str:
            return StabilityCondition('>', 300.0)
        
        # Fallback to simple string evaluation for unknown patterns
        class LegacyCondition(ConditionEvaluator):
            def __init__(self, condition_str):
                self.condition_str = condition_str
            
            def evaluate(self, context):
                # This would use the old string parsing logic
                return False
            
            def get_description(self):
                return self.condition_str
        
        return LegacyCondition(condition_str)


class AdaptationStrategy(Enum):
    """Adaptation strategies for different threat scenarios."""
    AGGRESSIVE = auto()      # Maximum evasion, performance secondary
    BALANCED = auto()        # Balance between security and performance
    STEALTH = auto()         # Minimize detectability
    PERFORMANCE = auto()     # Optimize for speed, minimal obfuscation
    DEFENSIVE = auto()       # Focus on maintaining connectivity


class SystemState(Enum):
    """Overall system operational states."""
    INITIALIZING = auto()
    NORMAL = auto()
    ADAPTING = auto()
    UNDER_ATTACK = auto()
    COMPROMISED = auto()
    RECOVERY = auto()


@dataclass
class AdaptationRule:
    """
    Rule for automatic system adaptation with robust condition evaluation.
    
    Refactored to use object-oriented condition evaluators instead of brittle
    string parsing for improved maintainability and reliability.
    """
    trigger_condition: ConditionEvaluator
    action: str
    priority: int
    cooldown: float = 30.0
    last_executed: float = 0.0
    description: str = ""


@dataclass
class PerformanceMetrics:
    """System-wide performance metrics."""
    timestamp: float
    overall_latency: float
    throughput: float
    success_rate: float
    detection_accuracy: float
    adaptation_overhead: float
    resource_usage: Dict[str, float] = field(default_factory=dict)


class AdaptiveControlLoop:
    """
    Adaptive Control Loop for SpectralFlow.
    
    Implements a sophisticated control system that:
    1. Continuously monitors network conditions and threats
    2. Adapts protocol behavior using ML-based decision making
    3. Coordinates all system components for optimal performance
    4. Provides self-healing and resilience capabilities
    """
    
    def __init__(self, 
                 adaptation_interval: float = 5.0,
                 learning_rate: float = 0.1,
                 max_adaptation_history: int = 1000):
        """
        Initialize Adaptive Control Loop.
        
        Args:
            adaptation_interval: How often to run adaptation logic (seconds)
            learning_rate: Learning rate for adaptation algorithms
            max_adaptation_history: Maximum adaptation events to store
        """
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.adaptation_interval = adaptation_interval
        self.learning_rate = learning_rate
        self.max_adaptation_history = max_adaptation_history
        
        # Component references (injected later)
        self.censorship_detector: Optional[CensorshipDetector] = None
        self.threat_monitor: Optional[ThreatMonitor] = None
        self.response_engine: Optional[ResponseEngine] = None
        self.quantum_obfuscator: Optional[QuantumObfuscator] = None
        self.adaptive_transport: Optional[AdaptiveTransport] = None
        self.mirror_network: Optional[MirrorNetwork] = None
        
        # Control state
        self.system_state = SystemState.INITIALIZING
        self.current_strategy = AdaptationStrategy.BALANCED
        self.is_running = False
        
        # Metrics and history
        self.performance_history: deque = deque(maxlen=max_adaptation_history)
        self.adaptation_history: deque = deque(maxlen=max_adaptation_history)
        self.threat_response_history: deque = deque(maxlen=max_adaptation_history)
        
        # Adaptation rules
        self.adaptation_rules: List[AdaptationRule] = self._initialize_adaptation_rules()
        
        # Performance tracking
        self.baseline_metrics: Optional[PerformanceMetrics] = None
        self.current_metrics: Optional[PerformanceMetrics] = None
        
        # Control loop task
        self.control_task: Optional[asyncio.Task] = None
        
        self.logger.info("Adaptive Control Loop initialized")
    def _initialize_adaptation_rules(self) -> List[AdaptationRule]:
        """
        Initialize default adaptation rules with robust condition evaluators.
        
        Replaced string-based conditions with object-oriented evaluators for
        improved maintainability and reliability as per Phase 3 requirements.
        """
        return [
            # High threat detection -> Aggressive mode
            AdaptationRule(
                trigger_condition=ThreatLevelCondition('>=', ThreatLevel.HIGH),
                action="set_strategy_aggressive",
                priority=1,
                cooldown=10.0,
                description="Switch to aggressive mode when high threat detected"
            ),
            
            # DPI detection -> Protocol hopping
            AdaptationRule(
                trigger_condition=CensorshipTypeCondition(CensorshipType.DPI_FILTERING),
                action="activate_protocol_hopping",
                priority=2,
                cooldown=5.0,
                description="Activate protocol hopping when DPI filtering detected"
            ),
            
            # IP blocking -> Mirror network switch
            AdaptationRule(
                trigger_condition=CensorshipTypeCondition(CensorshipType.IP_BLOCKING),
                action="switch_mirror_node",
                priority=2,
                cooldown=15.0,
                description="Switch mirror node when IP blocking detected"
            ),
            
            # Poor performance -> Performance mode
            AdaptationRule(
                trigger_condition=PerformanceCondition('success_rate', '<', 0.8),
                action="set_strategy_performance",
                priority=3,
                cooldown=30.0,
                description="Switch to performance mode when success rate is low"
            ),
            
            # Stable conditions -> Balanced mode
            AdaptationRule(
                trigger_condition=CompoundCondition(
                    ThreatLevelCondition('==', ThreatLevel.NONE),
                    'AND',
                    StabilityCondition('>', 300.0)
                ),
                action="set_strategy_balanced",
                priority=4,
                cooldown=60.0,
                description="Switch to balanced mode when conditions are stable"
            )
        ]
    
    async def initialize_components(self,
                                  censorship_detector: CensorshipDetector,
                                  threat_monitor: ThreatMonitor,
                                  response_engine: ResponseEngine,
                                  quantum_obfuscator: QuantumObfuscator,
                                  adaptive_transport: AdaptiveTransport,
                                  mirror_network: MirrorNetwork):
        """
        Initialize component references.
        
        Args:
            censorship_detector: ML-based censorship detection
            threat_monitor: Threat monitoring system
            response_engine: Automated response system
            quantum_obfuscator: Core obfuscation layer
            adaptive_transport: Transport layer coordinator
            mirror_network: Network layer coordinator
        """
        self.censorship_detector = censorship_detector
        self.threat_monitor = threat_monitor
        self.response_engine = response_engine
        self.quantum_obfuscator = quantum_obfuscator
        self.adaptive_transport = adaptive_transport
        self.mirror_network = mirror_network
        
        self.logger.info("All components initialized")
    
    async def start(self):
        """Start the adaptive control loop."""
        if self.is_running:
            self.logger.warning("Control loop already running")
            return
        
        self.is_running = True
        self.system_state = SystemState.NORMAL
        
        # Start main control loop
        self.control_task = asyncio.create_task(self._control_loop())
        
        self.logger.info("Adaptive control loop started")
    
    async def stop(self):
        """Stop the adaptive control loop."""
        self.is_running = False
        
        if self.control_task:
            self.control_task.cancel()
            try:
                await self.control_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Adaptive control loop stopped")
    
    async def _control_loop(self):
        """Main control loop that runs adaptation logic."""
        try:
            while self.is_running:
                start_time = time.time()
                
                try:
                    # 1. Collect current metrics
                    await self._collect_metrics()
                    
                    # 2. Analyze threats and conditions
                    threat_analysis = await self._analyze_threats()
                    
                    # 3. Evaluate adaptation rules
                    adaptations = await self._evaluate_adaptations(threat_analysis)
                    
                    # 4. Execute adaptations
                    if adaptations:
                        await self._execute_adaptations(adaptations)
                    
                    # 5. Update system state
                    await self._update_system_state(threat_analysis)
                    
                    # 6. Log performance
                    self._log_performance_metrics()
                    
                except Exception as e:
                    self.logger.error(f"Error in control loop iteration: {e}")
                
                # Wait for next iteration
                elapsed = time.time() - start_time
                sleep_time = max(0, self.adaptation_interval - elapsed)
                await asyncio.sleep(sleep_time)
                
        except asyncio.CancelledError:
            self.logger.info("Control loop cancelled")
        except Exception as e:
            self.logger.error(f"Control loop error: {e}")
            self.system_state = SystemState.COMPROMISED
    
    async def _collect_metrics(self):
        """Collect performance metrics from all components."""
        try:
            current_time = time.time()
            
            # Get metrics from components
            transport_metrics = {}
            network_metrics = {}
            security_metrics = {}
            
            if self.adaptive_transport:
                transport_metrics = await self.adaptive_transport.get_performance_metrics()
            
            if self.mirror_network:
                network_metrics = await self.mirror_network.get_performance_metrics()
            
            if self.censorship_detector:
                security_metrics = {
                    'threat_level': self.censorship_detector.current_threat_level.value,
                    'detection_confidence': getattr(self.censorship_detector, 'last_confidence', 0.0)
                }
            
            # Calculate overall metrics
            overall_latency = transport_metrics.get('avg_latency', 0.0)
            throughput = transport_metrics.get('throughput', 0.0)
            success_rate = network_metrics.get('success_rate', 1.0)
            
            # Create performance metrics object
            self.current_metrics = PerformanceMetrics(
                timestamp=current_time,
                overall_latency=overall_latency,
                throughput=throughput,
                success_rate=success_rate,
                detection_accuracy=security_metrics.get('detection_confidence', 0.0),
                adaptation_overhead=0.0,  # Calculate based on recent adaptations
                resource_usage={
                    'cpu_usage': 0.0,  # Would be measured in production
                    'memory_usage': 0.0,
                    'bandwidth_usage': throughput
                }
            )
            
            # Store in history
            self.performance_history.append(self.current_metrics)
            
            # Set baseline if not set
            if self.baseline_metrics is None and len(self.performance_history) > 10:
                self._calculate_baseline()
            
        except Exception as e:
            self.logger.error(f"Error collecting metrics: {e}")
    
    def _calculate_baseline(self):
        """Calculate baseline performance metrics."""
        if len(self.performance_history) < 10:
            return
        
        recent_metrics = list(self.performance_history)[-10:]
        
        avg_latency = statistics.mean(m.overall_latency for m in recent_metrics)
        avg_throughput = statistics.mean(m.throughput for m in recent_metrics)
        avg_success_rate = statistics.mean(m.success_rate for m in recent_metrics)
        
        self.baseline_metrics = PerformanceMetrics(
            timestamp=time.time(),
            overall_latency=avg_latency,
            throughput=avg_throughput,
            success_rate=avg_success_rate,
            detection_accuracy=0.0,
            adaptation_overhead=0.0
        )
        
        self.logger.info(f"Baseline metrics calculated: latency={avg_latency:.3f}s, "
                        f"throughput={avg_throughput:.0f}B/s, success_rate={avg_success_rate:.3f}")
    
    async def _analyze_threats(self) -> Dict[str, Any]:
        """Analyze current threat landscape."""
        threat_analysis = {
            'threat_level': ThreatLevel.NONE,
            'detected_censorship': [],
            'network_anomalies': [],
            'performance_degradation': False,
            'stability_duration': 0.0
        }
        
        try:
            # Get threat level from detector
            if self.censorship_detector:
                threat_analysis['threat_level'] = self.censorship_detector.current_threat_level
                
                # Get recent threats
                recent_threats = list(self.censorship_detector.threat_history)[-10:]
                threat_analysis['detected_censorship'] = [
                    t.threat_type for t in recent_threats 
                    if time.time() - t.timestamp < 300  # Last 5 minutes
                ]
            
            # Analyze performance degradation
            if self.current_metrics and self.baseline_metrics:
                latency_ratio = self.current_metrics.overall_latency / max(self.baseline_metrics.overall_latency, 0.001)
                throughput_ratio = self.current_metrics.throughput / max(self.baseline_metrics.throughput, 1)
                
                if (latency_ratio > 2.0 or throughput_ratio < 0.5 or 
                    self.current_metrics.success_rate < 0.8):
                    threat_analysis['performance_degradation'] = True
            
            # Calculate stability duration
            if len(self.performance_history) > 1:
                stable_since = None
                for i in range(len(self.performance_history) - 1, 0, -1):
                    metrics = self.performance_history[i]
                    if metrics.success_rate < 0.9:  # Not stable
                        stable_since = metrics.timestamp
                        break
                
                if stable_since:
                    threat_analysis['stability_duration'] = time.time() - stable_since
                else:
                    threat_analysis['stability_duration'] = time.time() - self.performance_history[0].timestamp
            
        except Exception as e:
            self.logger.error(f"Error analyzing threats: {e}")
        
        return threat_analysis
    async def _evaluate_adaptations(self, threat_analysis: Dict[str, Any]) -> List[AdaptationRule]:
        """Evaluate which adaptation rules should be triggered using new condition evaluators."""
        triggered_rules = []
        current_time = time.time()
        
        # Create evaluation context from threat analysis and current metrics
        context = {
            'threat_level': threat_analysis.get('threat_level', ThreatLevel.NONE),
            'detected_censorship': threat_analysis.get('detected_censorship', []),
            'stability_duration': threat_analysis.get('stability_duration', 0),
            'current_metrics': self.current_metrics,
            'threat_analysis': threat_analysis
        }
        
        for rule in self.adaptation_rules:
            try:
                # Check cooldown
                if current_time - rule.last_executed < rule.cooldown:
                    continue
                
                # Evaluate trigger condition using new evaluator system
                if rule.trigger_condition.evaluate(context):
                    triggered_rules.append(rule)
                    rule.last_executed = current_time
                    self.logger.debug(f"Rule triggered: {rule.description}")
                    
            except Exception as e:
                self.logger.error(f"Error evaluating rule '{rule.description}': {e}")
        
        # Sort by priority
        triggered_rules.sort(key=lambda r: r.priority)
        
        return triggered_rules
    
    async def _execute_adaptations(self, rules: List[AdaptationRule]):
        """Execute triggered adaptation rules."""
        for rule in rules:
            try:
                self.logger.info(f"Executing adaptation: {rule.action}")
                
                if rule.action == "set_strategy_aggressive":
                    await self._set_strategy(AdaptationStrategy.AGGRESSIVE)
                
                elif rule.action == "set_strategy_performance":
                    await self._set_strategy(AdaptationStrategy.PERFORMANCE)
                
                elif rule.action == "set_strategy_balanced":
                    await self._set_strategy(AdaptationStrategy.BALANCED)
                
                elif rule.action == "activate_protocol_hopping":
                    if self.adaptive_transport:
                        await self.adaptive_transport.enable_protocol_hopping()
                
                elif rule.action == "switch_mirror_node":
                    if self.mirror_network:
                        await self.mirror_network.switch_to_backup_node()
                
                # Record adaptation
                self.adaptation_history.append({
                    'timestamp': time.time(),
                    'action': rule.action,
                    'trigger': rule.trigger_condition,
                    'priority': rule.priority
                })
                
            except Exception as e:
                self.logger.error(f"Error executing adaptation {rule.action}: {e}")
    
    async def _set_strategy(self, strategy: AdaptationStrategy):
        """Set the overall adaptation strategy."""
        if self.current_strategy == strategy:
            return
        
        old_strategy = self.current_strategy
        self.current_strategy = strategy
        
        self.logger.info(f"Strategy changed: {old_strategy.name} -> {strategy.name}")
        
        # Configure components based on strategy
        if strategy == AdaptationStrategy.AGGRESSIVE:
            await self._configure_aggressive_mode()
        elif strategy == AdaptationStrategy.PERFORMANCE:
            await self._configure_performance_mode()
        elif strategy == AdaptationStrategy.BALANCED:
            await self._configure_balanced_mode()
        elif strategy == AdaptationStrategy.STEALTH:
            await self._configure_stealth_mode()
        elif strategy == AdaptationStrategy.DEFENSIVE:
            await self._configure_defensive_mode()
    
    async def _configure_aggressive_mode(self):
        """Configure all components for maximum evasion."""
        try:
            if self.quantum_obfuscator:
                await self.quantum_obfuscator.set_obfuscation_level(1.0)
            
            if self.adaptive_transport:
                await self.adaptive_transport.set_aggressiveness(1.0)
                await self.adaptive_transport.enable_steganography()
            
            if self.mirror_network:
                await self.mirror_network.increase_circuit_length()
                
        except Exception as e:
            self.logger.error(f"Error configuring aggressive mode: {e}")
    
    async def _configure_performance_mode(self):
        """Configure all components for maximum performance."""
        try:
            if self.quantum_obfuscator:
                await self.quantum_obfuscator.set_obfuscation_level(0.3)
            
            if self.adaptive_transport:
                await self.adaptive_transport.set_aggressiveness(0.2)
                await self.adaptive_transport.disable_steganography()
            
            if self.mirror_network:
                await self.mirror_network.optimize_for_speed()
                
        except Exception as e:
            self.logger.error(f"Error configuring performance mode: {e}")
    
    async def _configure_balanced_mode(self):
        """Configure all components for balanced operation."""
        try:
            if self.quantum_obfuscator:
                await self.quantum_obfuscator.set_obfuscation_level(0.6)
            
            if self.adaptive_transport:
                await self.adaptive_transport.set_aggressiveness(0.5)
            
            if self.mirror_network:
                await self.mirror_network.balance_security_performance()
                
        except Exception as e:
            self.logger.error(f"Error configuring balanced mode: {e}")
    
    async def _configure_stealth_mode(self):
        """Configure all components for maximum stealth."""
        try:
            if self.quantum_obfuscator:
                await self.quantum_obfuscator.set_obfuscation_level(0.9)
            
            if self.adaptive_transport:
                await self.adaptive_transport.enable_steganography()
                await self.adaptive_transport.minimize_traffic_signature()
            
            if self.mirror_network:
                await self.mirror_network.maximize_anonymity()
                
        except Exception as e:
            self.logger.error(f"Error configuring stealth mode: {e}")
    
    async def _configure_defensive_mode(self):
        """Configure all components for defensive operation."""
        try:
            if self.adaptive_transport:
                await self.adaptive_transport.enable_redundancy()
            
            if self.mirror_network:
                await self.mirror_network.increase_redundancy()
                
        except Exception as e:
            self.logger.error(f"Error configuring defensive mode: {e}")
    
    async def _update_system_state(self, threat_analysis: Dict[str, Any]):
        """Update overall system state based on current conditions."""
        old_state = self.system_state
        
        # Determine new state based on threat level and performance
        if threat_analysis['threat_level'].value >= ThreatLevel.CRITICAL.value:
            self.system_state = SystemState.UNDER_ATTACK
        elif threat_analysis['threat_level'].value >= ThreatLevel.MEDIUM.value:
            self.system_state = SystemState.ADAPTING
        elif threat_analysis['performance_degradation']:
            self.system_state = SystemState.ADAPTING
        else:
            self.system_state = SystemState.NORMAL
        
        if old_state != self.system_state:
            self.logger.info(f"System state changed: {old_state.name} -> {self.system_state.name}")
    
    def _log_performance_metrics(self):
        """Log current performance metrics."""
        if not self.current_metrics:
            return
        
        metrics = self.current_metrics
        self.logger.debug(
            f"Performance: latency={metrics.overall_latency:.3f}s, "
            f"throughput={metrics.throughput:.0f}B/s, "
            f"success_rate={metrics.success_rate:.3f}, "
            f"strategy={self.current_strategy.name}, "
            f"state={self.system_state.name}"
        )
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        recent_adaptations = len([
            a for a in self.adaptation_history 
            if time.time() - a['timestamp'] < 3600  # Last hour
        ])
        
        return {
            'system_state': self.system_state.name,
            'current_strategy': self.current_strategy.name,
            'threat_level': (self.censorship_detector.current_threat_level.name 
                           if self.censorship_detector else 'UNKNOWN'),
            'performance_metrics': asdict(self.current_metrics) if self.current_metrics else {},
            'recent_adaptations': recent_adaptations,
            'total_adaptations': len(self.adaptation_history),
            'uptime': time.time() - (self.performance_history[0].timestamp 
                                   if self.performance_history else time.time()),
            'components_online': {
                'censorship_detector': self.censorship_detector is not None,
                'threat_monitor': self.threat_monitor is not None,
                'response_engine': self.response_engine is not None,
                'quantum_obfuscator': self.quantum_obfuscator is not None,
                'adaptive_transport': self.adaptive_transport is not None,
                'mirror_network': self.mirror_network is not None
            }
        }
    
    async def force_adaptation(self, strategy: AdaptationStrategy):
        """Force a specific adaptation strategy."""
        self.logger.info(f"Forcing adaptation to {strategy.name}")
        await self._set_strategy(strategy)
    
    async def add_adaptation_rule(self, rule: AdaptationRule):
        """Add a new adaptation rule."""
        self.adaptation_rules.append(rule)
        self.adaptation_rules.sort(key=lambda r: r.priority)
        self.logger.info(f"Added adaptation rule: {rule.trigger_condition} -> {rule.action}")
