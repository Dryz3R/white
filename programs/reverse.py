import subprocess
import os
import lief
import pefile
import capstone
import keystone
from capstone import *
from keystone import *
import re
import hashlib
import json
from datetime import datetime

def analyze_binary(filename):
    if not os.path.exists(filename):
        print(f"File {filename} does not exist")
        return
    
    print(f"Analyzing binary: {filename}")
    analysis_results = {}
    
    analysis_results['basic_info'] = get_basic_info(filename)
    analysis_results['security_features'] = check_security_features(filename)
    analysis_results['imports_exports'] = analyze_imports_exports(filename)
    analysis_results['sections'] = analyze_sections(filename)
    analysis_results['strings'] = extract_strings(filename)
    analysis_results['disassembly'] = disassemble_code(filename)
    analysis_results['entropy'] = calculate_entropy(filename)
    analysis_results['hashes'] = calculate_hashes(filename)
    analysis_results['yara_scan'] = yara_scan(filename)
    analysis_results['behavior_analysis'] = behavioral_analysis(filename)
    
    generate_binary_report(analysis_results, filename)
    
    return analysis_results

def get_basic_info(filename):
    info = {}
    
    try:
        result = subprocess.run(['file', filename], capture_output=True, text=True)
        info['file_type'] = result.stdout.strip()
    except:
        info['file_type'] = 'Unknown'
    
    try:
        result = subprocess.run(['objdump', '-f', filename], capture_output=True, text=True)
        info['file_header'] = result.stdout
    except:
        pass
    
    info['size'] = os.path.getsize(filename)
    info['modified_time'] = datetime.fromtimestamp(os.path.getmtime(filename))
    info['accessed_time'] = datetime.fromtimestamp(os.path.getatime(filename))
    
    return info

def check_security_features(filename):
    security = {}
    
    try:
        binary = lief.parse(filename)
        
        if binary.format == lief.EXE_FORMATS.ELF:
            security['relro'] = check_relro(binary)
            security['canary'] = check_canary(binary)
            security['nx'] = check_nx(binary)
            security['pie'] = check_pie(binary)
            security['rpath'] = check_rpath(binary)
            security['runpath'] = check_runpath(binary)
            security['symbols_stripped'] = check_stripped(binary)
            
        elif binary.format == lief.EXE_FORMATS.PE:
            pe = pefile.PE(filename)
            security['aslr'] = check_pe_aslr(pe)
            security['dep'] = check_pe_dep(pe)
            security['authenticode'] = check_authenticode(pe)
            security['rich_header'] = check_rich_header(pe)
            
    except Exception as e:
        security['error'] = str(e)
    
    return security

def check_relro(binary):
    try:
        for segment in binary.segments:
            if segment.type == lief.ELF.SEGMENT_TYPES.GNU_RELRO:
                return "Full" if segment.virtual_size > 0 else "Partial"
        return "No RELRO"
    except:
        return "Unknown"

def check_canary(binary):
    try:
        symbols = binary.symbols
        for symbol in symbols:
            if symbol.name == '__stack_chk_fail':
                return "Canary found"
        return "No canary"
    except:
        return "Unknown"

def check_nx(binary):
    try:
        for segment in binary.segments:
            if not segment.has(lief.ELF.SEGMENT_FLAGS.X):
                return "NX enabled"
        return "NX disabled"
    except:
        return "Unknown"

def check_pie(binary):
    try:
        if binary.header.file_type == lief.ELF.ELF_CLASS.CLASS64:
            if binary.header.header_type == lief.ELF.ELF_TYPE.DYN:
                return "PIE enabled"
        return "PIE disabled"
    except:
        return "Unknown"

def check_rpath(binary):
    try:
        for entry in binary.dynamic_entries:
            if entry.tag == lief.ELF.DYNAMIC_TAGS.RPATH:
                return f"RPATH found: {entry.name}"
        return "No RPATH"
    except:
        return "Unknown"

def check_runpath(binary):
    try:
        for entry in binary.dynamic_entries:
            if entry.tag == lief.ELF.DYNAMIC_TAGS.RUNPATH:
                return f"RUNPATH found: {entry.name}"
        return "No RUNPATH"
    except:
        return "Unknown"

def check_stripped(binary):
    try:
        if not binary.symbols:
            return "Symbols stripped"
        return "Symbols present"
    except:
        return "Unknown"

def check_pe_aslr(pe):
    try:
        if pe.OPTIONAL_HEADER.DLL_CHARACTERISTICS & 0x0040:
            return "ASLR enabled"
        return "ASLR disabled"
    except:
        return "Unknown"

def check_pe_dep(pe):
    try:
        if pe.OPTIONAL_HEADER.DLL_CHARACTERISTICS & 0x0100:
            return "DEP enabled"
        return "DEP disabled"
    except:
        return "Unknown"

def check_authenticode(pe):
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            return "Authenticode signed"
        return "Not signed"
    except:
        return "Unknown"

def check_rich_header(pe):
    try:
        if hasattr(pe, 'RICH_HEADER'):
            return "Rich header present"
        return "No rich header"
    except:
        return "Unknown"

def analyze_imports_exports(filename):
    imports_exports = {}
    
    try:
        binary = lief.parse(filename)
        
        imports = {}
        for imported_lib in binary.imported_functions:
            lib_name = imported_lib.name
            functions = [func.name for func in imported_lib.entries]
            imports[lib_name] = functions
        
        imports_exports['imports'] = imports
        
        if hasattr(binary, 'exported_functions'):
            exports = [func.name for func in binary.exported_functions]
            imports_exports['exports'] = exports
            
    except Exception as e:
        imports_exports['error'] = str(e)
    
    try:
        result = subprocess.run(['nm', '-D', filename], capture_output=True, text=True)
        imports_exports['dynamic_symbols'] = result.stdout.split('\n')[:50]
    except:
        pass
    
    return imports_exports

def analyze_sections(filename):
    sections_info = {}
    
    try:
        result = subprocess.run(['readelf', '-S', filename], capture_output=True, text=True)
        sections_info['elf_sections'] = result.stdout
    except:
        pass
    
    try:
        result = subprocess.run(['objdump', '-h', filename], capture_output=True, text=True)
        sections_info['objdump_sections'] = result.stdout
    except:
        pass
    
    try:
        binary = lief.parse(filename)
        sections = []
        for section in binary.sections:
            section_info = {
                'name': section.name,
                'size': section.size,
                'virtual_size': section.virtual_size,
                'offset': section.offset,
                'entropy': section.entropy
            }
            sections.append(section_info)
        sections_info['detailed_sections'] = sections
    except:
        pass
    
    return sections_info

def extract_strings(filename):
    strings_result = {}
    
    try:
        result = subprocess.run(['strings', '-a', filename], capture_output=True, text=True)
        all_strings = result.stdout.split('\n')
        
        interesting_strings = []
        for string in all_strings:
            if len(string) > 6:
                if any(keyword in string.lower() for keyword in 
                      ['http://', 'https://', 'www.', '.com', '.org', '.net', 
                       'password', 'key', 'secret', 'token', 'api', 'admin']):
                    interesting_strings.append(string)
        
        strings_result['all_strings_count'] = len(all_strings)
        strings_result['interesting_strings'] = interesting_strings[:100]
        strings_result['urls'] = extract_urls(result.stdout)
        strings_result['ips'] = extract_ips(result.stdout)
        
    except Exception as e:
        strings_result['error'] = str(e)
    
    return strings_result

def extract_urls(text):
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    return re.findall(url_pattern, text)

def extract_ips(text):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, text)

def disassemble_code(filename):
    disassembly = {}
    
    try:
        binary = lief.parse(filename)
        
        if binary.format == lief.EXE_FORMATS.ELF:
            text_section = binary.get_section('.text')
            if text_section:
                code = text_section.content
                arch = CS_ARCH_X86
                mode = CS_MODE_64 if binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS64 else CS_MODE_32
                
                md = Cs(arch, mode)
                instructions = []
                
                for i in md.disasm(bytes(code), 0x1000):
                    instructions.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
                
                disassembly['text_section'] = instructions[:200]
        
        result = subprocess.run(['objdump', '-d', filename], capture_output=True, text=True)
        disassembly['objdump'] = result.stdout[:2000]
        
    except Exception as e:
        disassembly['error'] = str(e)
    
    return disassembly

def calculate_entropy(filename):
    entropy_results = {}
    
    try:
        with open(filename, 'rb') as f:
            data = f.read()
        
        if not data:
            return {"error": "Empty file"}
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        
        entropy_results['overall_entropy'] = entropy
        
        binary = lief.parse(filename)
        section_entropy = {}
        for section in binary.sections:
            section_entropy[section.name] = section.entropy
        entropy_results['section_entropy'] = section_entropy
        
    except Exception as e:
        entropy_results['error'] = str(e)
    
    return entropy_results

def calculate_hashes(filename):
    hashes = {}
    
    try:
        with open(filename, 'rb') as f:
            data = f.read()
        
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
        hashes['sha512'] = hashlib.sha512(data).hexdigest()
        
    except Exception as e:
        hashes['error'] = str(e)
    
    return hashes

def yara_scan(filename):
    yara_results = {}
    
    try:
        rules = """
        rule suspicious_strings {
            strings:
                $a = "http://" nocase
                $b = "https://" nocase
                $c = "www." nocase
                $d = "password" nocase
                $e = "admin" nocase
            condition:
                any of them
        }
        
        rule packed_executable {
            condition:
                pe.sections[0].entropy > 7.0
        }
        """
        
        import yara
        compiled_rules = yara.compile(source=rules)
        matches = compiled_rules.match(filename)
        
        yara_results['matches'] = [str(match) for match in matches]
        
    except ImportError:
        yara_results['error'] = "YARA not installed"
    except Exception as e:
        yara_results['error'] = str(e)
    
    return yara_results

def behavioral_analysis(filename):
    behavior = {}
    
    try:
        result = subprocess.run(['strace', '-f', '-e', 'trace=file,process,network', filename, '--help'], 
                              capture_output=True, text=True, timeout=10)
        behavior['system_calls'] = result.stderr.split('\n')[:50]
    except:
        behavior['system_calls'] = "Strace failed"
    
    try:
        result = subprocess.run(['ltrace', filename, '--help'], 
                              capture_output=True, text=True, timeout=10)
        behavior['library_calls'] = result.stdout.split('\n')[:50]
    except:
        behavior['library_calls'] = "Ltrace failed"
    
    return behavior

def generate_binary_report(analysis_results, filename):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"binary_analysis_{os.path.basename(filename)}_{timestamp}.json"
    
    with open(report_filename, 'w') as f:
        json.dump(analysis_results, f, indent=2, default=str)
    
    print(f"Analysis report saved to: {report_filename}")
    
    print_summary(analysis_results)

def print_summary(results):
    print("\n=== BINARY ANALYSIS SUMMARY ===")
    
    if 'basic_info' in results:
        print(f"File Type: {results['basic_info'].get('file_type', 'Unknown')}")
        print(f"File Size: {results['basic_info'].get('size', 0)} bytes")
    
    if 'security_features' in results:
        print("\nSecurity Features:")
        for feature, value in results['security_features'].items():
            if feature != 'error':
                print(f"  {feature}: {value}")
    
    if 'hashes' in results:
        print(f"\nSHA256: {results['hashes'].get('sha256', 'Unknown')}")
    
    if 'imports_exports' in results and 'imports' in results['imports_exports']:
        imports = results['imports_exports']['imports']
        print(f"\nImported Libraries: {len(imports)}")
        for lib in list(imports.keys())[:5]:
            print(f"  - {lib}")
    
    if 'strings' in results:
        print(f"\nStrings Found: {results['strings'].get('all_strings_count', 0)}")
        print(f"Interesting Strings: {len(results['strings'].get('interesting_strings', []))}")
        print(f"URLs Found: {len(results['strings'].get('urls', []))}")
        print(f"IPs Found: {len(results['strings'].get('ips', []))}")