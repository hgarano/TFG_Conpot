from pymodbus.client import ModbusTcpClient

# Configurar la conexión con el servidor Modbus
client = ModbusTcpClient("172.17.0.2", port=5020)

if client.connect():
    print("Conexión establecida al servidor Modbus")

    # PRUEBA 1 : Leer un Input Register (Analógico)
    response_analog = client.read_input_registers(30001, 8, slave=2)
    if not response_analog.isError():
        print(f"Valor del registro ANALÓGICO: {response_analog.registers}")
    else:
        print(f"Error al leer registro ANALÓGICO: {response_analog}")

    # PRUEBA 2: Leer el estado actual de los Coils antes de modificarlos
    response_coils_before = client.read_coils(1, 8, slave=1)
    if not response_coils_before.isError():
        print(f"Estado de los Coils antes de la modificación: {response_coils_before.bits}")
    else:
        print(f"Error al leer Coils antes de la modificación: {response_coils_before}")

    # PRUEBA 3: Resetear todos los Coils a OFF (0)
    reset_coils = client.write_coils(1, [0] * 8, slave=1)
    if not reset_coils.isError():
        print("Todos los Coils han sido reiniciados a OFF (0).")
    else:
        print(f"Error al resetear los Coils: {reset_coils}")

    # PRUEBA 4: Aplicar nueva configuración de Coils
    new_coil_values = [1, 1, 1, 1, 1, 1, 1, 1]  # ENCENDER TODOS
    print(f"Modificación a aplicar en los Coils: {new_coil_values}")

    write_coils = client.write_coils(1, new_coil_values, slave=1)
    if not write_coils.isError():
        print("Los valores de los Coils se han registrado y modificado correctamente.")
    else:
        print(f"Error al escribir en Coils: {write_coils}")

    # PRUEBA 5: Leer nuevamente los Coils para verificar la modificación
    response_coils_after = client.read_coils(1, 8, slave=1)
    if not response_coils_after.isError():
        print(f"Estado de los Coils después de la modificación: {response_coils_after.bits}")
    else:
        print(f"Error al leer Coils después de la modificación: {response_coils_after}")

    # Cerrar conexión
    client.close()
else:
    print("No se pudo conectar a Modbus en Conpot.")
