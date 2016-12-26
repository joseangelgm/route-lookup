
/* 	PRACTICA DE CONMUTACION DE PAQUETES: ROUTE LOOKUP	 */
	
/*	ALVARO GAMBOA ROSADO - 100291932 	*/

#include "io.h"

#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>


int flag = 0;	// Variable para comprobacion de errores


int main (int argc,char * argv[]) {

	/* COMPROBACION DE LOS ARGUMENTOS DE ENTRADA */
	/**************************************************************************/
	char * mensaje = basename(argv[0]);
	if ((argc != 3)) {
		printf("\nERROR AL INTRODUCIR ARGUMENTOS:\nUso correcto: %s <RIB> <InputPacketFile>\n", mensaje);
		printf("\t<RIB>: Fichero ASCII que contiene la tabla de rutas.\n");
		printf("\t<InputPacketFile>: Fichero ASCII con un listado de direcciones IP a procesar.\n");
		exit(-1);
	}


	/* INICIALIZAR IO */
	/******************/
	flag = initializeIO(argv[1],argv[2]);
	if (flag!=OK){
		printIOExplanationError(flag);
	}


	/* VARIABLES */
	/*************/
	unsigned short *TBL24 = (unsigned short*) calloc (16777216, sizeof(unsigned short)); // Tabla de tamaño 2^24
	unsigned short *TBLlong = (unsigned short*) calloc (256, sizeof(unsigned short)); 	 // Tabla de tamaño variable
	uint32_t prefijo = 0;	// Direccion IP del prefijo
	int prefixLength = 0;	// Tamaño del prefijo
	int outInterface = 0;	// Interfaz de salida

	int por_defecto = 0;			// Existencia o no de ruta por defecto (0 o 1)
	int interfaz_por_defecto = 0;	// Numero de la interfaz por defecto
	int indice = 0;					// Utilizada segun necesidades como indice en las tablas
	short offset = 0;				// Controla la direccion introducida en la entrada de la tabla grande para redireccionar a la pequeña
	int posiciones = 0;				// Numero de entradas a rellenar segun el prefijo y la longitud del prefijo
	int final = 0;					// Auxiliar

	int i = 0;	// Recorrido en bucles

	uint32_t ip = 0;			// Direccion ip de entrada
	struct timeval t_inicial;	// Tiempo inicial
	struct timeval t_final;		// Tiempo final
	double searchingTime = 0;	// Tiempo empleado en la busqueda
	short accesos = 0;			// Numero de accesos a tablas para un paquete
	short contenido = 0;		// Contenido de una entrada determinada de las tablas

	short processedPackets = 0;				// Numero total de paquetes procesados
	short totalTableAccesses = 0;			// Numero total de accesos a las tablas
	double totalPacketProcessingTime = 0;	// Tiempo total de procesamiento de todos los paquetes
	double averageTableAccesses = 0;		// Media de accesos a tablas por paquete
	double averagePacketProcessingTime = 0;	// Media de tiempo de procesamiento por paquete


	/* INSERTAR TABLA DE RUTAS */
	/***************************/
	while (1){
		flag = readFIBLine(&prefijo, &prefixLength, &outInterface);

		if (flag == REACHED_EOF){ // Fin del archivo --> Fin del bucle
			break;
		}
		if (flag == BAD_ROUTING_TABLE){ // Error al leer la tabla --> Mensaje de error y fin del programa
			printIOExplanationError(flag);
		}
		if (flag == OK){ // Lectura correcta
			indice = prefijo >> 8;
			
			if (prefixLength == 0){ // LONGITUD DE PREFIJO ES 0 --> RUTA POR DEFECTO
				por_defecto = 1;
				interfaz_por_defecto = outInterface;
			}

			if ((prefixLength <= 24) && (prefixLength != 0)){ // LONGITUD DE PREFIJO MENOR O IGUAL A /24
				posiciones = (int)pow(2, 24-prefixLength);
				i=0;
				while (i != posiciones){
					TBL24[indice+i] = ((short)outInterface)&32767; //Pongo un 0 en el bit mas significativo (Primero de los 16)
					i++;
				}

			}
			

			if (prefixLength >= 25){ // PREFIJO MAYOR QUE /24

				if (TBL24[indice] == 0){ // SI NO HAY NADA EN LA ENTRADA

					TBL24[indice] = offset|(-32768); //Pongo un 1 en el bit mas significativo (Primero de los 16)

					TBLlong = (unsigned short*)realloc(TBLlong, sizeof(short)*((offset+1)*256)); // Aumento en 256 el tamaño de la tabla pequeña
					
					indice = prefijo&255; //Me quedo con el ultimo byte del prefijo

					final = (int)pow(2, 32-prefixLength) + indice; // Donde parar de rellenar
					while (indice != final){
						TBLlong[(offset*256)+indice] = (short)outInterface;
						indice++;
					}
					offset++;

				} else{ // SI HAY ALGO EN LA ENTRADA

					if ((TBL24[indice]&(-32768)) == 0){ //Hay un 0 en el primer bit --> HAY UNA INTERFAZ

						TBL24[indice] = offset|(-32768); //Pongo un 1 en el bit mas significativo (Primero de los 16). Quito la interfaz y pongo el offset
						
						TBLlong = (unsigned short*)realloc(TBLlong, sizeof(short)*((offset+1)*256)); // Aumento en 256 el tamaño de la tabla pequeña
						
						indice = prefijo&255; //Me quedo con el ultimo byte del prefijo

						final = (int)pow(2, 32-prefixLength) + indice;
						while (indice != final){
							TBLlong[(offset*256)+indice] = (short)outInterface;
							indice++;
						}
						offset++;

					} else{ //Hay un 1 en el primer bit --> HAY UNA DIRECCION
						short direccion = TBL24[indice]&32767; //Me quedo con la direccion quitandole el 1 del primer bit
						
						indice = prefijo&255; //Me quedo con el ultimo byte
						final = (int)pow(2, 32-prefixLength) + indice;
						while (indice != final){
							TBLlong[(direccion*256)+indice] = (short)outInterface;
							indice++;
						}
					}
				}
			}
		}
	}
	

	/* ENCAMINAMIENTO DE LOS PAQUETES */
	/**********************************/
	while (1){
		flag = readInputPacketFileLine(&ip);

		if (flag == REACHED_EOF){ // Fin del archivo --> Fin del bucle
			break;
		}
		if (flag == BAD_INPUT_FILE){ // Error al leer el archivo --> Mensaje de error y fin del programa
			printIOExplanationError(flag);
		}
		if (flag == OK){ // Lectura correcta
			accesos = 0;
			gettimeofday(&t_inicial, NULL); // Tiempo inicial 

			indice = ip >> 8;
			if (TBL24[indice] == 0){ //Hay un 0 en memoria
				outInterface=0;
				accesos++;

			}else{ //Hay algo en memoria
				accesos++;
				contenido = TBL24[indice];
				if ((contenido&(-32768)) == 0){ //Hay un 0 en el primer bit --> HAY UNA INTERFAZ
					outInterface = (int) contenido;

				}else{ //Hay un 1 en el primer bit --> HAY UNA DIRECCION
					accesos++;
					outInterface = (int) TBLlong[((contenido&32767)*256)+(ip&255)];
				}

			}

			gettimeofday(&t_final, NULL); // Tiempo final

			if ((outInterface==0) && (por_defecto==0)){ // No hay ruta por defecto, resultado MISS
				printOutputLine(ip, outInterface, &t_inicial, &t_final, &searchingTime, accesos);
			}else if ((outInterface==0) && (por_defecto==1)){ // Hay ruta por defecto, resultado ruta por defecto
				printOutputLine(ip, interfaz_por_defecto, &t_inicial, &t_final, &searchingTime, accesos);
			}else{ // Resto de los casos
				printOutputLine(ip, outInterface, &t_inicial, &t_final, &searchingTime, accesos);
			}
			
			processedPackets++; // Incremento numero de paquetes totales
			totalTableAccesses = totalTableAccesses + accesos; // Incremento el numero de accesos a tablas totales
			totalPacketProcessingTime = totalPacketProcessingTime + searchingTime; // Incremento el tiempo total de procesamiento de paquetes
		}
	}


	/* SUMARIO */
	/***********/
	averageTableAccesses = totalTableAccesses/processedPackets; 						// Media de accesos totales a tablas por paquete
	averagePacketProcessingTime = totalPacketProcessingTime/processedPackets;			// Media de tiempo de procesamiento por paquete
	printSummary(processedPackets, averageTableAccesses, averagePacketProcessingTime);	// Imprimo sumario


	/* LIBERACION DE MEMORIA */
	/*************************/
	free(TBL24);
	free(TBLlong);
	freeIO();

	return 0;
}
