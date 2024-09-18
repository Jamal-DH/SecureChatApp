import psutil
import platform
import subprocess
import GPUtil
from tabulate import tabulate
import logging
from functools import wraps
import time
import os
import argparse
import json

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def time_it(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            end_time = time.time()
            logging.info(f"{func.__name__} executed in {end_time - start_time:.4f} seconds")
            return result
        except Exception as e:
            logging.error(f"Error in {func.__name__}: {e}", exc_info=True)
            return None
    return wrapper

@time_it
def get_cpu_info():
    """Retrieve CPU information."""
    try:
        cpu_freq = psutil.cpu_freq()
        cpu_info = {
            'Physical Cores': psutil.cpu_count(logical=False),
            'Total Cores': psutil.cpu_count(logical=True),
            'Max Frequency': f"{cpu_freq.max:.2f}Mhz",
            'Min Frequency': f"{cpu_freq.min:.2f}Mhz",
            'Current Frequency': f"{cpu_freq.current:.2f}Mhz",
            'CPU Usage Per Core': [f"{x}%" for x in psutil.cpu_percent(percpu=True, interval=1)],
            'Total CPU Usage': f"{psutil.cpu_percent()}%"
        }
        # Try to get CPU temperature if possible
        try:
            import wmi
            w = wmi.WMI(namespace=r"root\wmi")
            temperature_info = w.MSAcpi_ThermalZoneTemperature()[0].CurrentTemperature
            cpu_info['Temperature'] = f"{(temperature_info / 10.0) - 273.15:.2f} °C"
        except Exception as e:
            cpu_info['Temperature'] = "N/A"
            logging.warning(f"Could not retrieve CPU temperature: {e}")
        return cpu_info
    except Exception as e:
        logging.error(f"Failed to get CPU info: {e}", exc_info=True)
        return None

@time_it
def get_memory_info():
    """Retrieve memory information."""
    try:
        svmem = psutil.virtual_memory()
        memory_info = {
            'Total': get_size(svmem.total),
            'Available': get_size(svmem.available),
            'Used': get_size(svmem.used),
            'Percentage': f"{svmem.percent}%",
        }
        return memory_info
    except Exception as e:
        logging.error(f"Failed to get memory info: {e}", exc_info=True)
        return None

@time_it
def get_disk_info():
    """Retrieve disk information."""
    try:
        partitions = psutil.disk_partitions()
        disk_info = []
        for partition in partitions:
            partition_usage = psutil.disk_usage(partition.mountpoint)
            disk_info.append({
                'Device': partition.device,
                'Mountpoint': partition.mountpoint,
                'File System Type': partition.fstype,
                'Total Size': get_size(partition_usage.total),
                'Used': get_size(partition_usage.used),
                'Free': get_size(partition_usage.free),
                'Percentage': f"{partition_usage.percent}%",
                'Health': get_disk_health(partition.device)
            })
        return disk_info
    except Exception as e:
        logging.error(f"Failed to get disk info: {e}", exc_info=True)
        return []

@time_it
def get_disk_health(drive_letter):
    """Check disk health using WMIC."""
    try:
        result = subprocess.run(['wmic', 'diskdrive', 'get', 'status'], capture_output=True, text=True, check=True)
        status_lines = result.stdout.splitlines()
        return "Healthy" if any("OK" in line for line in status_lines) else "Unhealthy"
    except subprocess.CalledProcessError as e:
        logging.error(f"Subprocess error checking disk health: {e}", exc_info=True)
        return f"Error: {e}"
    except Exception as e:
        logging.error(f"Unexpected error checking disk health: {e}", exc_info=True)
        return f"Error: {e}"

@time_it
def get_gpu_info():
    """Retrieve GPU information."""
    try:
        gpus = GPUtil.getGPUs()
        gpu_info = [
            {
                'GPU': gpu.name,
                'Total Memory': f"{gpu.memoryTotal}MB",
                'Free Memory': f"{gpu.memoryFree}MB",
                'Used Memory': f"{gpu.memoryUsed}MB",
                'GPU Load': f"{gpu.load * 100:.2f}%",
                'Temperature': f"{gpu.temperature} °C",
            } for gpu in gpus
        ]
        return gpu_info
    except Exception as e:
        logging.error(f"Failed to get GPU info: {e}", exc_info=True)
        return []

def get_size(bytes, suffix="B"):
    """Scale bytes to its proper format."""
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f} {unit}{suffix}"
        bytes /= factor

@time_it
def get_system_info():
    """Retrieve system information."""
    try:
        uname = platform.uname()
        system_info = {
            'System': uname.system,
            'Node Name': uname.node,
            'Release': uname.release,
            'Version': uname.version,
            'Machine': uname.machine,
            'Processor': uname.processor,
        }
        return system_info
    except Exception as e:
        logging.error(f"Failed to get system info: {e}", exc_info=True)
        return None

@time_it
def evaluate_system(cpu_info, memory_info, disk_info, gpu_info):
    """Evaluate the system based on the gathered information."""
    evaluation = []
    try:
        if cpu_info and cpu_info.get('Physical Cores', 0) >= 4:
            evaluation.append("CPU: 100% - Sufficient number of physical cores.")
        if cpu_info and float(cpu_info.get('Current Frequency', '0Mhz').replace('Mhz', '')) >= 2000:
            evaluation.append("CPU: 100% - Sufficient frequency.")
        if memory_info and float(memory_info.get('Total', '0 GB').replace(' GB', '')) >= 8:
            evaluation.append("Memory: 100% - Sufficient RAM.")
        if not gpu_info or all(float(gpu.get('Total Memory', '0MB').replace('MB', '')) >= 2048 for gpu in gpu_info):
            evaluation.append("GPU: 100% - Sufficient GPU memory.")
        for disk in disk_info:
            if disk.get('Health', '') == 'Healthy':
                evaluation.append(f"Disk {disk.get('Device', 'N/A')}: 100% - Healthy.")
        if not evaluation:
            evaluation.append("System seems to be in good condition.")
    except Exception as e:
        logging.error(f"Error in system evaluation: {e}", exc_info=True)
        evaluation = [f"Error in evaluation: {e}"]
    return evaluation

@time_it
def cpu_benchmark():
    """Perform a CPU-intensive task to benchmark the CPU."""
    try:
        start_time = time.time()
        for _ in range(10000000):
            pass
        end_time = time.time()
        benchmark_result = end_time - start_time
        return f"CPU Benchmark: {benchmark_result:.4f} seconds for 10,000,000 iterations"
    except Exception as e:
        logging.error(f"Failed to benchmark CPU: {e}", exc_info=True)
        return f"Error: {e}"

@time_it
def memory_benchmark():
    """Measure memory read/write speeds."""
    try:
        start_time = time.time()
        data = bytearray(500 * 1024 * 1024)  # 500 MB
        end_time = time.time()
        write_time = end_time - start_time

        start_time = time.time()
        _ = data[:]
        end_time = time.time()
        read_time = end_time - start_time

        return f"Memory Benchmark: Write - {write_time:.4f} seconds, Read - {read_time:.4f} seconds"
    except Exception as e:
        logging.error(f"Failed to benchmark memory: {e}", exc_info=True)
        return f"Error: {e}"

@time_it
def disk_benchmark():
    """Measure disk read/write speeds."""
    try:
        start_time = time.time()
        with open("testfile", "wb") as f:
            f.write(bytearray(500 * 1024 * 1024))  # Write 500 MB
        end_time = time.time()
        write_time = end_time - start_time

        start_time = time.time()
        with open("testfile", "rb") as f:
            _ = f.read()
        end_time = time.time()
        read_time = end_time - start_time

        return f"Disk Benchmark: Write - {write_time:.4f} seconds, Read - {read_time:.4f} seconds"
    except Exception as e:
        logging.error(f"Failed to benchmark disk: {e}", exc_info=True)
        return f"Error: {e}"
    finally:
        try:
            os.remove("testfile")
        except Exception as e:
            logging.error(f"Failed to delete benchmark file: {e}", exc_info=True)

def save_results_to_file(results, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"Results saved to {filename}")
    except Exception as e:
        logging.error(f"Failed to save results to file: {e}", exc_info=True)

def parse_arguments():
    parser = argparse.ArgumentParser(description='System Information and Benchmarking Script')
    parser.add_argument('--cpu-info', action='store_true', help='Retrieve CPU information')
    parser.add_argument('--memory-info', action='store_true', help='Retrieve memory information')
    parser.add_argument('--disk-info', action='store_true', help='Retrieve disk information')
    parser.add_argument('--gpu-info', action='store_true', help='Retrieve GPU information')
    parser.add_argument('--benchmark', action='store_true', help='Run benchmarks')
    parser.add_argument('--output', type=str, help='File to save the results')
    return parser.parse_args()

def main():
    """Main function to gather and display system information and evaluation."""
    logging.info("Starting system information and benchmarking script...")
    
    args = parse_arguments()
    
    system_info = get_system_info() if args.cpu_info or args.memory_info or args.disk_info or args.gpu_info else None
    cpu_info = get_cpu_info() if args.cpu_info else None
    memory_info = get_memory_info() if args.memory_info else None
    disk_info = get_disk_info() if args.disk_info else None
    gpu_info = get_gpu_info() if args.gpu_info else None

    if system_info:
        logging.info("System Information:")
        print(tabulate(system_info.items(), headers=['Component', 'Details']))

    if cpu_info:
        logging.info("CPU Information:")
        print(tabulate(cpu_info.items(), headers=['Component', 'Details']))
    else:
        logging.error("Failed to retrieve CPU information.")

    if memory_info:
        logging.info("Memory Information:")
        print(tabulate(memory_info.items(), headers=['Component', 'Details']))
    else:
        logging.error("Failed to retrieve memory information.")

    if disk_info:
        logging.info("Disk Information:")
        for info in disk_info:
            print(tabulate(info.items(), headers=['Component', 'Details']))
            print()
    else:
        logging.error("Failed to retrieve disk information.")

    if gpu_info:
        logging.info("GPU Information:")
        for info in gpu_info:
            print(tabulate(info.items(), headers=['Component', 'Details']))
            print()
    else:
        logging.info("No GPU found.")

    if args.benchmark:
        logging.info("Running Benchmarks...")

        cpu_bench = cpu_benchmark()
        memory_bench = memory_benchmark()
        disk_bench = disk_benchmark()

        logging.info("Benchmark Results:")
        print(cpu_bench)
        print(memory_bench)
        print(disk_bench)

    if args.output:
        results = {
            'System Information': system_info,
            'CPU Information': cpu_info,
            'Memory Information': memory_info,
            'Disk Information': disk_info,
            'GPU Information': gpu_info
        }
        save_results_to_file(results, args.output)

if __name__ == "__main__":
    main()
