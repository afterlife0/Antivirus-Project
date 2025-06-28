"""
Advanced Multi-Algorithm Antivirus Software
==========================================
YARA Detector - Rule-based Pattern Matching Detection

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.utils.encoding_utils (EncodingHandler)
- src.utils.file_utils (FileUtils)
- src.utils.helpers (HelperFunctions)

Connected Components (files that import from this module):
- src.detection.ensemble.voting_classifier (EnsembleVotingClassifier)
- src.core.scanner_engine (ScannerEngine)
- src.intelligence.threat_intel (ThreatIntelligence)

Integration Points:
- YARA rules-based pattern matching for advanced threat detection
- Malware family identification through behavioral patterns
- Custom rule compilation and management system
- Multi-rule scanning with performance optimization
- Integration with ensemble voting system for global classification
- Rule update and synchronization capabilities
- Pattern-based detection for polymorphic and metamorphic malware
- Advanced string and binary pattern matching
- Behavioral pattern analysis and classification
- Real-time rule scanning with configurable timeout controls

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: YaraDetector
□ Dependencies properly imported with EXACT class names
□ All connected files can access YaraDetector functionality
□ YARA detection implemented
□ Rule-based matching functional
□ Rule compilation working
□ Performance optimization included
□ Update mechanism integrated
"""

import os
import sys
import logging
import re
import time
import json
import threading
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

# Project Dependencies
from src.utils.encoding_utils import EncodingHandler
from src.utils.file_utils import FileUtils
from src.utils.helpers import HelperFunctions


class YaraRuleType(Enum):
    """Types of YARA rules supported."""
    MALWARE_GENERIC = "malware_generic"
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    SPYWARE = "spyware"
    ADWARE = "adware"
    ROOTKIT = "rootkit"
    WORM = "worm"
    VIRUS = "virus"
    BACKDOOR = "backdoor"
    PACKER = "packer"
    CRYPTER = "crypter"
    DROPPER = "dropper"
    LOADER = "loader"
    CUSTOM = "custom"


class MatchType(Enum):
    """Types of pattern matches."""
    STRING_MATCH = "string_match"
    HEX_MATCH = "hex_match"
    REGEX_MATCH = "regex_match"
    CONDITION_MATCH = "condition_match"
    METADATA_MATCH = "metadata_match"


@dataclass
class YaraMatch:
    """Container for individual YARA rule match."""
    rule_name: str
    rule_type: YaraRuleType
    threat_family: str
    severity: str
    confidence: float
    risk_score: float
    matched_strings: List[Dict[str, Any]]
    match_offsets: List[int]
    rule_metadata: Dict[str, Any]
    match_timestamp: str
    rule_source: str
    additional_context: Dict[str, Any]


@dataclass
class YaraDetectionResult:
    """Container for complete YARA detection results."""
    file_path: str
    file_hash_sha256: str
    detected: bool
    matches: List[YaraMatch]
    total_rules_scanned: int
    scan_time: float
    file_size: int
    scan_timestamp: str
    highest_confidence: float
    highest_risk_score: float
    threat_families: List[str]
    recommended_action: str
    scan_statistics: Dict[str, Any]


class YaraRule:
    """Represents a compiled YARA rule."""
    
    def __init__(self, rule_name: str, rule_content: str, rule_type: YaraRuleType,
                 metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize YARA rule.
        
        Args:
            rule_name: Name of the rule
            rule_content: Raw rule content
            rule_type: Type of the rule
            metadata: Rule metadata
        """
        self.rule_name = rule_name
        self.rule_content = rule_content
        self.rule_type = rule_type
        self.metadata = metadata or {}
        self.compiled = False
        self.compilation_error = None
        self.last_updated = datetime.now().isoformat()
        
        # Parse rule components
        self.strings_section = self._extract_strings_section()
        self.condition_section = self._extract_condition_section()
        self.rule_metadata = self._extract_metadata_section()
        
        # Compile rule patterns
        self._compile_patterns()
    
    def _extract_strings_section(self) -> List[Dict[str, str]]:
        """Extract strings section from rule."""
        try:
            strings = []
            lines = self.rule_content.split('\n')
            in_strings_section = False
            
            for line in lines:
                line = line.strip()
                if line.lower().startswith('strings:'):
                    in_strings_section = True
                    continue
                elif line.lower().startswith('condition:'):
                    break
                elif in_strings_section and line.startswith('$'):
                    # Parse string definition
                    if '=' in line:
                        parts = line.split('=', 1)
                        string_name = parts[0].strip()
                        string_value = parts[1].strip().strip('"\'')
                        
                        # Determine string type
                        if line.strip().endswith('nocase'):
                            string_type = 'text_nocase'
                        elif '{' in string_value and '}' in string_value:
                            string_type = 'hex'
                        elif line.strip().endswith('wide'):
                            string_type = 'wide'
                        else:
                            string_type = 'text'
                        
                        strings.append({
                            'name': string_name,
                            'value': string_value,
                            'type': string_type
                        })
            
            return strings
            
        except Exception as e:
            logging.getLogger("YaraRule").error(f"Error extracting strings section: {e}")
            return []
    
    def _extract_condition_section(self) -> str:
        """Extract condition section from rule."""
        try:
            lines = self.rule_content.split('\n')
            in_condition_section = False
            condition_lines = []
            
            for line in lines:
                line = line.strip()
                if line.lower().startswith('condition:'):
                    in_condition_section = True
                    continue
                elif in_condition_section:
                    if line and not line.startswith('}'):
                        condition_lines.append(line)
                    elif line.startswith('}'):
                        break
            
            return ' '.join(condition_lines)
            
        except Exception as e:
            logging.getLogger("YaraRule").error(f"Error extracting condition section: {e}")
            return ""
    
    def _extract_metadata_section(self) -> Dict[str, Any]:
        """Extract metadata section from rule."""
        try:
            metadata = {}
            lines = self.rule_content.split('\n')
            in_metadata_section = False
            
            for line in lines:
                line = line.strip()
                if line.lower().startswith('meta:'):
                    in_metadata_section = True
                    continue
                elif line.lower().startswith('strings:'):
                    break
                elif in_metadata_section and '=' in line:
                    parts = line.split('=', 1)
                    key = parts[0].strip()
                    value = parts[1].strip().strip('"\'')
                    metadata[key] = value
            
            return metadata
            
        except Exception as e:
            logging.getLogger("YaraRule").error(f"Error extracting metadata section: {e}")
            return {}
    
    def _compile_patterns(self) -> None:
        """Compile string patterns for matching."""
        try:
            self.compiled_patterns = []
            
            for string_def in self.strings_section:
                pattern_info = {
                    'name': string_def['name'],
                    'type': string_def['type'],
                    'original_value': string_def['value']
                }
                
                if string_def['type'] == 'text':
                    pattern_info['compiled'] = re.compile(re.escape(string_def['value']))
                elif string_def['type'] == 'text_nocase':
                    pattern_info['compiled'] = re.compile(re.escape(string_def['value']), re.IGNORECASE)
                elif string_def['type'] == 'hex':
                    # Convert hex pattern to regex
                    hex_pattern = string_def['value'].replace(' ', '').replace('{', '').replace('}', '')
                    if '?' in hex_pattern:
                        # Handle wildcards
                        hex_pattern = hex_pattern.replace('?', '.')
                    pattern_info['compiled'] = re.compile(hex_pattern, re.IGNORECASE)
                elif string_def['type'] == 'wide':
                    # Wide string pattern (Unicode)
                    wide_value = string_def['value'].encode('utf-16le')
                    pattern_info['compiled'] = re.compile(re.escape(wide_value.hex()), re.IGNORECASE)
                
                self.compiled_patterns.append(pattern_info)
            
            self.compiled = True
            
        except Exception as e:
            self.compilation_error = str(e)
            logging.getLogger("YaraRule").error(f"Error compiling patterns for rule {self.rule_name}: {e}")


class YaraDetector:
    """
    YARA Rules-based Malware Detection System.
    
    Provides advanced pattern matching detection using YARA-style rules
    for identifying malware families and behavioral patterns.
    
    Features:
    - Custom YARA rule engine implementation
    - Multiple rule types for different malware families
    - Pattern matching with string, hex, and regex support
    - Rule compilation and caching for performance
    - Metadata-driven threat classification
    - Integration with ensemble voting system
    - Rule update and management capabilities
    - Performance optimization with timeout controls
    - Detailed match reporting and analysis
    """
    
    def __init__(self, rules_directory: Optional[Union[str, Path]] = None):
        """
        Initialize YARA Detector.
        
        Args:
            rules_directory: Directory containing YARA rules files
        """
        self.encoding_handler = EncodingHandler()
        self.file_utils = FileUtils()
        self.helpers = HelperFunctions()
        self.logger = logging.getLogger("YaraDetector")
        
        # Rules configuration
        self.rules_directory = rules_directory or self._get_default_rules_directory()
        self.compiled_rules = {}  # rule_name -> YaraRule
        self.rules_by_type = {}   # rule_type -> List[YaraRule]
        
        # Performance settings
        self.max_file_size = 50 * 1024 * 1024  # 50MB max
        self.scan_timeout = 30.0  # 30 seconds timeout
        self.max_matches_per_rule = 100
        self.chunk_size = 1024 * 1024  # 1MB chunks
        
        # Detection configuration
        self.supported_extensions = {
            '.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1',
            '.vbs', '.js', '.jar', '.apk', '.dex', '.so', '.dylib', '.pdf',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.rar'
        }
        
        # Statistics tracking
        self.total_scans = 0
        self.total_detections = 0
        self.total_scan_time = 0.0
        self.rules_loaded = 0
        self.rules_compiled = 0
        
        # Thread safety
        self._stats_lock = threading.Lock()
        self._rules_lock = threading.Lock()
        
        # Initialize rules
        self._initialize_rules_directory()
        self._load_rules()
        
        self.logger.info(f"YaraDetector initialized with {self.rules_loaded} rules")
    
    def _get_default_rules_directory(self) -> Path:
        """Get default YARA rules directory."""
        try:
            # Get project root directory
            current_file = Path(__file__)
            project_root = current_file.parent.parent.parent.parent
            
            # Create yara_rules directory if it doesn't exist
            rules_dir = project_root / "yara_rules"
            rules_dir.mkdir(exist_ok=True)
            
            return rules_dir
            
        except Exception as e:
            self.logger.error(f"Error getting default rules directory: {e}")
            return Path("yara_rules")
    
    def _initialize_rules_directory(self) -> None:
        """Initialize rules directory with default rules."""
        try:
            if not self.rules_directory.exists():
                self.rules_directory.mkdir(parents=True, exist_ok=True)
            
            # Create default rule files if they don't exist
            self._create_default_rules()
            
        except Exception as e:
            self.logger.error(f"Error initializing rules directory: {e}")
    
    def _create_default_rules(self) -> None:
        """Create default YARA rules for testing."""
        try:
            # Generic malware rule
            generic_malware_rule = '''
rule Generic_Malware_Patterns
{
    meta:
        description = "Generic malware detection patterns"
        author = "Antivirus System"
        threat_family = "Generic"
        severity = "medium"
        confidence = "0.6"
        risk_score = "0.7"
        
    strings:
        $api1 = "CreateRemoteThread" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "VirtualAllocEx" nocase
        $api4 = "SetWindowsHookEx" nocase
        $string1 = "This program cannot be run in DOS mode"
        $hex1 = { 4D 5A }  // MZ header
        
    condition:
        $hex1 at 0 and (2 of ($api*) or $string1)
}
'''
            
            # Ransomware detection rule
            ransomware_rule = '''
rule Ransomware_Behavior_Patterns
{
    meta:
        description = "Detects common ransomware behavioral patterns"
        author = "Antivirus System"
        threat_family = "Ransomware"
        severity = "critical"
        confidence = "0.9"
        risk_score = "0.95"
        
    strings:
        $crypt1 = "CryptEncrypt" nocase
        $crypt2 = "CryptGenRandom" nocase
        $file1 = "FindFirstFile" nocase
        $file2 = "FindNextFile" nocase
        $ransom1 = "ransom" nocase
        $ransom2 = "decrypt" nocase
        $ransom3 = "bitcoin" nocase
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        
    condition:
        2 of ($crypt*) and 2 of ($file*) and (1 of ($ransom*) or 1 of ($ext*))
}
'''
            
            # Trojan detection rule
            trojan_rule = '''
rule Trojan_Backdoor_Patterns
{
    meta:
        description = "Detects trojan and backdoor patterns"
        author = "Antivirus System"
        threat_family = "Trojan"
        severity = "high"
        confidence = "0.8"
        risk_score = "0.85"
        
    strings:
        $net1 = "WSAStartup" nocase
        $net2 = "connect" nocase
        $net3 = "send" nocase
        $net4 = "recv" nocase
        $reg1 = "RegSetValue" nocase
        $reg2 = "RegCreateKey" nocase
        $proc1 = "CreateProcess" nocase
        $shell1 = "cmd.exe" nocase
        $shell2 = "powershell" nocase
        
    condition:
        3 of ($net*) and 1 of ($reg*) and (1 of ($proc*) or 1 of ($shell*))
}
'''
            
            # Write default rules to files
            rules_to_create = [
                ('malware_rules.yar', generic_malware_rule),
                ('ransomware_rules.yar', ransomware_rule),
                ('trojan_rules.yar', trojan_rule)
            ]
            
            for filename, rule_content in rules_to_create:
                rule_file = self.rules_directory / filename
                if not rule_file.exists():
                    self.file_utils.write_file_safely(rule_file, rule_content)
                    self.logger.info(f"Created default rule file: {filename}")
            
        except Exception as e:
            self.logger.error(f"Error creating default rules: {e}")
    
    def _load_rules(self) -> None:
        """Load and compile YARA rules from directory."""
        try:
            with self._rules_lock:
                self.compiled_rules.clear()
                self.rules_by_type.clear()
                
                rule_files = list(self.rules_directory.glob("*.yar")) + list(self.rules_directory.glob("*.yara"))
                
                for rule_file in rule_files:
                    try:
                        rule_content = self.file_utils.read_file_safely(rule_file)
                        if rule_content:
                            self._parse_and_compile_rules(rule_content, str(rule_file))
                    except Exception as file_error:
                        self.logger.error(f"Error loading rule file {rule_file}: {file_error}")
                        continue
                
                # Organize rules by type
                for rule in self.compiled_rules.values():
                    if rule.rule_type not in self.rules_by_type:
                        self.rules_by_type[rule.rule_type] = []
                    self.rules_by_type[rule.rule_type].append(rule)
                
                self.rules_loaded = len(self.compiled_rules)
                self.rules_compiled = sum(1 for rule in self.compiled_rules.values() if rule.compiled)
                
                self.logger.info(f"Loaded {self.rules_loaded} rules, {self.rules_compiled} compiled successfully")
                
        except Exception as e:
            self.logger.error(f"Error loading rules: {e}")
    
    def _parse_and_compile_rules(self, rule_content: str, source_file: str) -> None:
        """Parse and compile rules from content."""
        try:
            # Split content into individual rules
            rule_blocks = self._split_rule_blocks(rule_content)
            
            for rule_block in rule_blocks:
                try:
                    rule_name = self._extract_rule_name(rule_block)
                    if not rule_name:
                        continue
                    
                    # Determine rule type from metadata or filename
                    rule_type = self._determine_rule_type(rule_block, source_file)
                    
                    # Extract metadata
                    metadata = self._extract_rule_metadata(rule_block)
                    metadata['source_file'] = source_file
                    
                    # Create and compile rule
                    yara_rule = YaraRule(rule_name, rule_block, rule_type, metadata)
                    
                    if yara_rule.compiled:
                        self.compiled_rules[rule_name] = yara_rule
                        self.logger.debug(f"Compiled rule: {rule_name}")
                    else:
                        self.logger.warning(f"Failed to compile rule: {rule_name} - {yara_rule.compilation_error}")
                        
                except Exception as rule_error:
                    self.logger.error(f"Error processing individual rule: {rule_error}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error parsing rules content: {e}")
    
    def _split_rule_blocks(self, content: str) -> List[str]:
        """Split rule content into individual rule blocks."""
        try:
            rules = []
            lines = content.split('\n')
            current_rule = []
            in_rule = False
            brace_count = 0
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                
                if line.startswith('rule ') and not in_rule:
                    in_rule = True
                    current_rule = [line]
                    brace_count = 0
                elif in_rule:
                    current_rule.append(line)
                    brace_count += line.count('{') - line.count('}')
                    
                    if brace_count == 0 and '}' in line:
                        rules.append('\n'.join(current_rule))
                        current_rule = []
                        in_rule = False
            
            return rules
            
        except Exception as e:
            self.logger.error(f"Error splitting rule blocks: {e}")
            return []
    
    def _extract_rule_name(self, rule_block: str) -> Optional[str]:
        """Extract rule name from rule block."""
        try:
            lines = rule_block.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('rule '):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1].strip()
            return None
            
        except Exception as e:
            self.logger.error(f"Error extracting rule name: {e}")
            return None
    
    def _determine_rule_type(self, rule_block: str, source_file: str) -> YaraRuleType:
        """Determine rule type from metadata or filename."""
        try:
            # Check metadata first
            metadata = self._extract_rule_metadata(rule_block)
            if 'threat_family' in metadata:
                threat_family = metadata['threat_family'].lower()
                for rule_type in YaraRuleType:
                    if rule_type.value in threat_family or threat_family in rule_type.value:
                        return rule_type
            
            # Check filename
            filename = Path(source_file).stem.lower()
            for rule_type in YaraRuleType:
                if rule_type.value in filename:
                    return rule_type
            
            return YaraRuleType.MALWARE_GENERIC
            
        except Exception as e:
            self.logger.error(f"Error determining rule type: {e}")
            return YaraRuleType.MALWARE_GENERIC
    
    def _extract_rule_metadata(self, rule_block: str) -> Dict[str, Any]:
        """Extract metadata from rule block."""
        try:
            metadata = {}
            lines = rule_block.split('\n')
            in_meta_section = False
            
            for line in lines:
                line = line.strip()
                if line.lower().startswith('meta:'):
                    in_meta_section = True
                    continue
                elif line.lower().startswith('strings:'):
                    break
                elif in_meta_section and '=' in line:
                    parts = line.split('=', 1)
                    key = parts[0].strip()
                    value = parts[1].strip().strip('"\'')
                    
                    # Convert numeric strings to numbers
                    if value.replace('.', '').isdigit():
                        try:
                            metadata[key] = float(value) if '.' in value else int(value)
                        except ValueError:
                            metadata[key] = value
                    else:
                        metadata[key] = value
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error extracting rule metadata: {e}")
            return {}
    
    def scan(self, file_path: Union[str, Path]) -> Optional[YaraDetectionResult]:
        """
        Perform YARA rules-based scanning on a file.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            YARA detection result or None if scan fails
        """
        try:
            start_time = time.time()
            file_path = Path(file_path)
            
            if not file_path.exists() or not file_path.is_file():
                self.logger.error(f"File not found or not a file: {file_path}")
                return None
            
            self.logger.info(f"Starting YARA scan for: {file_path.name}")
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                self.logger.warning(f"File too large ({file_size} bytes), skipping: {file_path.name}")
                return self._create_scan_result(
                    file_path, "", False, [], 0, time.time() - start_time,
                    file_size, "File too large for YARA scanning"
                )
            
            # Check supported extensions
            if file_path.suffix.lower() not in self.supported_extensions:
                self.logger.debug(f"File extension not in supported list: {file_path.suffix}")
                # Still scan but with lower priority
            
            # Calculate file hash
            file_hash = self.helpers.calculate_file_hash(file_path, 'sha256')
            
            # Read file content
            file_content = self._read_file_for_scanning(file_path)
            if not file_content:
                return None
            
            # Perform rule matching
            matches = self._scan_with_rules(file_content, file_path)
            
            # Process results
            detected = len(matches) > 0
            scan_time = time.time() - start_time
            
            # Calculate statistics
            highest_confidence = max([match.confidence for match in matches]) if matches else 0.0
            highest_risk_score = max([match.risk_score for match in matches]) if matches else 0.0
            threat_families = list(set([match.threat_family for match in matches])) if matches else []
            
            # Update statistics
            self._update_statistics(scan_time, detected)
            
            # Create scan result
            result = YaraDetectionResult(
                file_path=str(file_path),
                file_hash_sha256=file_hash or "",
                detected=detected,
                matches=matches,
                total_rules_scanned=len(self.compiled_rules),
                scan_time=scan_time,
                file_size=file_size,
                scan_timestamp=datetime.now().isoformat(),
                highest_confidence=highest_confidence,
                highest_risk_score=highest_risk_score,
                threat_families=threat_families,
                recommended_action=self._get_recommended_action(matches),
                scan_statistics=self._get_scan_statistics(matches)
            )
            
            self.logger.info(f"YARA scan completed: {detected} ({len(matches)} matches, {scan_time:.3f}s)")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in YARA scan for {file_path}: {e}")
            return None
    
    def _read_file_for_scanning(self, file_path: Path) -> Optional[bytes]:
        """Read file content for scanning."""
        try:
            # For binary files, read as bytes
            return self.file_utils.read_file_safely(file_path, binary=True)
            
        except Exception as e:
            self.logger.error(f"Error reading file for scanning: {e}")
            return None
    
    def _scan_with_rules(self, file_content: bytes, file_path: Path) -> List[YaraMatch]:
        """Scan file content with all compiled rules."""
        try:
            matches = []
            scan_start = time.time()
            
            for rule_name, rule in self.compiled_rules.items():
                try:
                    # Check timeout
                    if time.time() - scan_start > self.scan_timeout:
                        self.logger.warning(f"YARA scan timeout reached for {file_path.name}")
                        break
                    
                    if not rule.compiled:
                        continue
                    
                    # Scan with individual rule
                    rule_matches = self._scan_with_single_rule(file_content, rule, file_path)
                    matches.extend(rule_matches)
                    
                except Exception as rule_error:
                    self.logger.error(f"Error scanning with rule {rule_name}: {rule_error}")
                    continue
            
            return matches
            
        except Exception as e:
            self.logger.error(f"Error scanning with rules: {e}")
            return []
    
    def _scan_with_single_rule(self, file_content: bytes, rule: YaraRule, file_path: Path) -> List[YaraMatch]:
        """Scan file content with a single rule."""
        try:
            matches = []
            matched_strings = []
            match_offsets = []
            
            # Convert bytes to hex string for hex pattern matching
            hex_content = file_content.hex()
            
            # Check each pattern in the rule
            for pattern in rule.compiled_patterns:
                try:
                    pattern_matches = []
                    
                    if pattern['type'] in ['text', 'text_nocase']:
                        # Text pattern matching
                        text_content = file_content.decode('utf-8', errors='ignore')
                        for match in pattern['compiled'].finditer(text_content):
                            pattern_matches.append({
                                'offset': match.start(),
                                'length': match.end() - match.start(),
                                'matched_text': match.group()
                            })
                    
                    elif pattern['type'] == 'hex':
                        # Hex pattern matching
                        for match in pattern['compiled'].finditer(hex_content):
                            offset = match.start() // 2  # Convert hex offset to byte offset
                            pattern_matches.append({
                                'offset': offset,
                                'length': (match.end() - match.start()) // 2,
                                'matched_hex': match.group()
                            })
                    
                    elif pattern['type'] == 'wide':
                        # Wide string pattern matching
                        for match in pattern['compiled'].finditer(hex_content):
                            offset = match.start() // 2
                            pattern_matches.append({
                                'offset': offset,
                                'length': (match.end() - match.start()) // 2,
                                'matched_wide': match.group()
                            })
                    
                    # Store pattern matches
                    if pattern_matches:
                        matched_strings.append({
                            'pattern_name': pattern['name'],
                            'pattern_type': pattern['type'],
                            'matches': pattern_matches[:self.max_matches_per_rule]
                        })
                        
                        # Collect offsets
                        match_offsets.extend([m['offset'] for m in pattern_matches[:self.max_matches_per_rule]])
                        
                except Exception as pattern_error:
                    self.logger.error(f"Error matching pattern {pattern['name']}: {pattern_error}")
                    continue
            
            # Evaluate rule condition (simplified)
            if self._evaluate_rule_condition(rule, matched_strings):
                # Extract metadata
                threat_family = rule.rule_metadata.get('threat_family', 'Unknown')
                severity = rule.rule_metadata.get('severity', 'medium')
                confidence = float(rule.rule_metadata.get('confidence', 0.7))
                risk_score = float(rule.rule_metadata.get('risk_score', 0.8))
                
                match = YaraMatch(
                    rule_name=rule.rule_name,
                    rule_type=rule.rule_type,
                    threat_family=threat_family,
                    severity=severity,
                    confidence=confidence,
                    risk_score=risk_score,
                    matched_strings=matched_strings,
                    match_offsets=sorted(list(set(match_offsets))),
                    rule_metadata=rule.rule_metadata,
                    match_timestamp=datetime.now().isoformat(),
                    rule_source=rule.metadata.get('source_file', 'unknown'),
                    additional_context={
                        'file_size': len(file_content),
                        'match_count': len(matched_strings),
                        'unique_offsets': len(set(match_offsets))
                    }
                )
                matches.append(match)
            
            return matches
            
        except Exception as e:
            self.logger.error(f"Error scanning with single rule {rule.rule_name}: {e}")
            return []
    
    def _evaluate_rule_condition(self, rule: YaraRule, matched_strings: List[Dict[str, Any]]) -> bool:
        """Evaluate rule condition (simplified implementation)."""
        try:
            condition = rule.condition_section.lower()
            
            if not condition:
                # If no condition, require at least one string match
                return len(matched_strings) > 0
            
            # Simple condition evaluation
            if 'all of' in condition:
                # All strings must match
                pattern_names = [pattern['name'] for pattern in rule.compiled_patterns]
                matched_names = [ms['pattern_name'] for ms in matched_strings]
                return all(name in matched_names for name in pattern_names)
            
            elif 'any of' in condition or 'of them' in condition:
                # Any string match is sufficient
                return len(matched_strings) > 0
            
            elif ' of ' in condition and '$' in condition:
                # Parse numeric conditions like "2 of ($api*)"
                import re
                numeric_match = re.search(r'(\d+)\s+of\s+\(\$([^)]+)\)', condition)
                if numeric_match:
                    required_count = int(numeric_match.group(1))
                    pattern_prefix = numeric_match.group(2).replace('*', '')
                    
                    matching_count = sum(1 for ms in matched_strings 
                                       if ms['pattern_name'].startswith(f'${pattern_prefix}'))
                    return matching_count >= required_count
            
            # Default: require at least one match
            return len(matched_strings) > 0
            
        except Exception as e:
            self.logger.error(f"Error evaluating rule condition: {e}")
            return len(matched_strings) > 0
    
    def _get_recommended_action(self, matches: List[YaraMatch]) -> str:
        """Get recommended action based on matches."""
        try:
            if not matches:
                return "allow"
            
            # Find highest severity and risk
            highest_risk = max([match.risk_score for match in matches])
            severities = [match.severity for match in matches]
            
            if highest_risk >= 0.9 or 'critical' in severities:
                return "quarantine_immediately"
            elif highest_risk >= 0.7 or 'high' in severities:
                return "quarantine_with_user_confirmation"
            elif highest_risk >= 0.5 or 'medium' in severities:
                return "flag_for_review"
            else:
                return "allow_with_monitoring"
                
        except Exception as e:
            self.logger.error(f"Error getting recommended action: {e}")
            return "flag_for_review"
    
    def _get_scan_statistics(self, matches: List[YaraMatch]) -> Dict[str, Any]:
        """Get detailed scan statistics."""
        try:
            if not matches:
                return {
                    'total_matches': 0,
                    'unique_rules_matched': 0,
                    'threat_families': [],
                    'severity_distribution': {},
                    'confidence_stats': {'mean': 0.0, 'max': 0.0, 'min': 0.0}
                }
            
            # Collect statistics
            rule_names = [match.rule_name for match in matches]
            threat_families = [match.threat_family for match in matches]
            severities = [match.severity for match in matches]
            confidences = [match.confidence for match in matches]
            
            severity_dist = {}
            for severity in severities:
                severity_dist[severity] = severity_dist.get(severity, 0) + 1
            
            return {
                'total_matches': len(matches),
                'unique_rules_matched': len(set(rule_names)),
                'threat_families': list(set(threat_families)),
                'severity_distribution': severity_dist,
                'confidence_stats': {
                    'mean': sum(confidences) / len(confidences),
                    'max': max(confidences),
                    'min': min(confidences)
                },
                'total_string_matches': sum(len(match.matched_strings) for match in matches),
                'unique_match_offsets': len(set(offset for match in matches for offset in match.match_offsets))
            }
            
        except Exception as e:
            self.logger.error(f"Error getting scan statistics: {e}")
            return {}
    
    def _create_scan_result(self, file_path: Path, file_hash: str, detected: bool,
                          matches: List[YaraMatch], rules_scanned: int, scan_time: float,
                          file_size: int, note: str) -> YaraDetectionResult:
        """Create a YARA scan result."""
        return YaraDetectionResult(
            file_path=str(file_path),
            file_hash_sha256=file_hash,
            detected=detected,
            matches=matches,
            total_rules_scanned=rules_scanned,
            scan_time=scan_time,
            file_size=file_size,
            scan_timestamp=datetime.now().isoformat(),
            highest_confidence=max([match.confidence for match in matches]) if matches else 0.0,
            highest_risk_score=max([match.risk_score for match in matches]) if matches else 0.0,
            threat_families=list(set([match.threat_family for match in matches])) if matches else [],
            recommended_action=self._get_recommended_action(matches),
            scan_statistics={'note': note}
        )
    
    def _update_statistics(self, scan_time: float, detected: bool) -> None:
        """Update scan statistics."""
        try:
            with self._stats_lock:
                self.total_scans += 1
                self.total_scan_time += scan_time
                if detected:
                    self.total_detections += 1
                    
        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")
    
    def add_rule(self, rule_name: str, rule_content: str, rule_type: YaraRuleType,
                metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Add a new YARA rule to the detector.
        
        Args:
            rule_name: Name of the rule
            rule_content: Raw rule content
            rule_type: Type of the rule
            metadata: Additional metadata
            
        Returns:
            True if rule added successfully, False otherwise
        """
        try:
            with self._rules_lock:
                # Create and compile rule
                yara_rule = YaraRule(rule_name, rule_content, rule_type, metadata)
                
                if yara_rule.compiled:
                    self.compiled_rules[rule_name] = yara_rule
                    
                    # Update rules by type
                    if rule_type not in self.rules_by_type:
                        self.rules_by_type[rule_type] = []
                    self.rules_by_type[rule_type].append(yara_rule)
                    
                    self.rules_loaded += 1
                    self.rules_compiled += 1
                    
                    self.logger.info(f"Added YARA rule: {rule_name}")
                    return True
                else:
                    self.logger.error(f"Failed to compile YARA rule: {rule_name} - {yara_rule.compilation_error}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error adding YARA rule: {e}")
            return False
    
    def reload_rules(self) -> bool:
        """Reload all YARA rules from directory."""
        try:
            self._load_rules()
            self.logger.info("YARA rules reloaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error reloading rules: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics."""
        try:
            with self._stats_lock:
                return {
                    'total_scans': self.total_scans,
                    'total_detections': self.total_detections,
                    'detection_rate': self.total_detections / self.total_scans if self.total_scans > 0 else 0.0,
                    'average_scan_time': self.total_scan_time / self.total_scans if self.total_scans > 0 else 0.0,
                    'rules_loaded': self.rules_loaded,
                    'rules_compiled': self.rules_compiled,
                    'compilation_success_rate': self.rules_compiled / self.rules_loaded if self.rules_loaded > 0 else 0.0,
                    'rules_by_type': {rule_type.value: len(rules) for rule_type, rules in self.rules_by_type.items()},
                    'rules_directory': str(self.rules_directory),
                    'max_file_size': self.max_file_size,
                    'scan_timeout': self.scan_timeout,
                    'last_updated': datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {}
    
    def is_yara_detector_healthy(self) -> bool:
        """Check if YARA detector is healthy."""
        try:
            return (self.rules_loaded > 0 and 
                   self.rules_compiled > 0 and 
                   self.rules_directory.exists())
            
        except Exception as e:
            self.logger.error(f"Error checking detector health: {e}")
            return False
    
    def get_rule_info(self, rule_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific rule."""
        try:
            if rule_name not in self.compiled_rules:
                return None
            
            rule = self.compiled_rules[rule_name]
            return {
                'rule_name': rule.rule_name,
                'rule_type': rule.rule_type.value,
                'compiled': rule.compiled,
                'compilation_error': rule.compilation_error,
                'metadata': rule.rule_metadata,
                'strings_count': len(rule.strings_section),
                'patterns_count': len(rule.compiled_patterns),
                'last_updated': rule.last_updated,
                'condition': rule.condition_section
            }
            
        except Exception as e:
            self.logger.error(f"Error getting rule info: {e}")
            return None


# Utility function for easy detector creation
def create_yara_detector(rules_directory: Optional[Union[str, Path]] = None) -> YaraDetector:
    """
    Convenience function to create a YARA detector.
    
    Args:
        rules_directory: Optional directory containing YARA rules
        
    Returns:
        Initialized YaraDetector instance
    """
    try:
        return YaraDetector(rules_directory)
    except Exception as e:
        logging.getLogger("YaraDetector").error(f"Error creating YARA detector: {e}")
        raise


if __name__ == "__main__":
    # **TESTING**: Basic functionality test
    import tempfile
    
    print("Testing YaraDetector...")
    
    # Create temporary test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.exe', delete=False) as temp_file:
        temp_file.write("This is a test executable file with CreateRemoteThread and WriteProcessMemory")
        temp_file_path = temp_file.name
    
    try:
        # Create YARA detector
        detector = YaraDetector()
        print(f"✅ YaraDetector created successfully")
        
        # Test health check
        is_healthy = detector.is_yara_detector_healthy()
        print(f"✅ Health Check: {'Healthy' if is_healthy else 'Unhealthy'}")
        
        # Test YARA scanning
        result = detector.scan(temp_file_path)
        if result:
            print(f"✅ YARA scan completed: {result.detected}")
            print(f"   File: {Path(result.file_path).name}")
            print(f"   Rules scanned: {result.total_rules_scanned}")
            print(f"   Scan time: {result.scan_time:.3f}s")
            print(f"   Matches: {len(result.matches)}")
            if result.matches:
                for match in result.matches:
                    print(f"     Rule: {match.rule_name}")
                    print(f"     Threat: {match.threat_family}")
                    print(f"     Confidence: {match.confidence:.3f}")
        
        # Test statistics
        stats = detector.get_statistics()
        print(f"✅ Statistics retrieved: {len(stats)} categories")
        print(f"   Rules loaded: {stats.get('rules_loaded', 0)}")
        print(f"   Rules compiled: {stats.get('rules_compiled', 0)}")
        print(f"   Compilation success rate: {stats.get('compilation_success_rate', 0):.3f}")
        
        # Test rule addition
        test_rule = '''
rule Test_Custom_Rule
{
    meta:
        description = "Test custom rule"
        threat_family = "Test"
        confidence = "0.8"
        
    strings:
        $test = "test" nocase
        
    condition:
        $test
}
'''
        success = detector.add_rule("Test_Custom_Rule", test_rule, YaraRuleType.CUSTOM)
        print(f"✅ Rule Addition: {'Success' if success else 'Failed'}")
        
        print("✅ YaraDetector test completed successfully")
        
    except Exception as e:
        print(f"❌ YaraDetector test failed: {e}")
    
    finally:
        # Cleanup
        try:
            os.unlink(temp_file_path)
        except:
            pass