import psutil
import platform
import subprocess
import GPUtil
from tabulate import tabulate

def get_cpu_info():
    cpu_info = {}
    cpu_info['Physical Cores'] = psutil.cpu_count(logical=False)
    cpu_info['Total Cores'] = psutil.cpu_count(logical=True)
    cpufreq = psutil.cpu_freq()
    cpu_info['Max Frequency'] = f"{cpufreq.max:.2f}Mhz"
    cpu_info['Min Frequency'] = f"{cpufreq.min:.2f}Mhz"
    cpu_info['Current Frequency'] = f"{cpufreq.current:.2f}Mhz"
    cpu_info['CPU Usage Per Core'] = [f"{x}%" for x in psutil.cpu_percent(percpu=True, interval=1)]
    cpu_info['Total CPU Usage'] = f"{psutil.cpu_percent()}%"
    return cpu_info

def get_memory_info():
    svmem = psutil.virtual_memory()
    memory_info = {}
    memory_info['Total'] = f"{get_size(svmem.total)}"
    memory_info['Available'] = f"{get_size(svmem.available)}"
    memory_info['Used'] = f"{get_size(svmem.used)}"
    memory_info['Percentage'] = f"{svmem.percent}%"
    return memory_info

def get_disk_info():
    partitions = psutil.disk_partitions()
    disk_info = []
    for partition in partitions:
        partition_info = {}
        partition_info['Device'] = partition.device
        partition_info['Mountpoint'] = partition.mountpoint
        partition_info['File System Type'] = partition.fstype
        partition_usage = psutil.disk_usage(partition.mountpoint)
        partition_info['Total Size'] = f"{get_size(partition_usage.total)}"
        partition_info['Used'] = f"{get_size(partition_usage.used)}"
        partition_info['Free'] = f"{get_size(partition_usage.free)}"
        partition_info['Percentage'] = f"{partition_usage.percent}%"
        disk_info.append(partition_info)
    return disk_info

def get_gpu_info():
    gpus = GPUtil.getGPUs()
    gpu_info = []
    for gpu in gpus:
        gpu_info.append({
            'GPU': gpu.name,
            'Total Memory': f"{gpu.memoryTotal}MB",
            'Free Memory': f"{gpu.memoryFree}MB",
            'Used Memory': f"{gpu.memoryUsed}MB",
            'GPU Load': f"{gpu.load*100}%",
            'Temperature': f"{gpu.temperature} C"
        })
    return gpu_info

def get_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f} {unit}{suffix}"
        bytes /= factor

def get_system_info():
    uname = platform.uname()
    return {
        'System': uname.system,
        'Node Name': uname.node,
        'Release': uname.release,
        'Version': uname.version,
        'Machine': uname.machine,
        'Processor': uname.processor,
    }

def evaluate_system(cpu_info, memory_info, disk_info, gpu_info):
    evaluation = []
    if cpu_info['Physical Cores'] < 4:
        evaluation.append("CPU has less than 4 physical cores. Consider a more powerful CPU for better performance.")
    if float(cpu_info['Current Frequency'].replace('Mhz', '')) < 2000:
        evaluation.append("CPU frequency is less than 2.0GHz. Consider a higher frequency CPU for better performance.")
    if float(memory_info['Total'].replace('GB', '')) < 8:
        evaluation.append("RAM is less than 8GB. Consider adding more RAM.")
    if not gpu_info:
        evaluation.append("No dedicated GPU found. Consider adding a dedicated GPU for better graphics performance.")
    else:
        for gpu in gpu_info:
            if float(gpu['Total Memory'].replace('MB', '')) < 2048:
                evaluation.append("GPU memory is less than 2GB. Consider a GPU with more memory for better graphics performance.")
    if not evaluation:
        evaluation.append("System seems to be in good condition.")
    return evaluation

def main():
    print("Gathering system information...")
    
    system_info = get_system_info()
    cpu_info = get_cpu_info()
    memory_info = get_memory_info()
    disk_info = get_disk_info()
    gpu_info = get_gpu_info()

    print("\nSystem Information:")
    print(tabulate(system_info.items(), headers=['Component', 'Details']))

    print("\nCPU Information:")
    print(tabulate(cpu_info.items(), headers=['Component', 'Details']))

    print("\nMemory Information:")
    print(tabulate(memory_info.items(), headers=['Component', 'Details']))

    print("\nDisk Information:")
    for info in disk_info:
        print(tabulate(info.items(), headers=['Component', 'Details']))
        print()

    if gpu_info:
        print("\nGPU Information:")
        for info in gpu_info:
            print(tabulate(info.items(), headers=['Component', 'Details']))
            print()
    else:
        print("\nNo GPU found.")

    print("\nEvaluation:")
    evaluation = evaluate_system(cpu_info, memory_info, disk_info, gpu_info)
    for comment in evaluation:
        print(comment)

if __name__ == "__main__":
    main()
