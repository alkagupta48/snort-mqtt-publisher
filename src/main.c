/*******************************************************************************
 * Copyright (c) 2020.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution. 
 *
 * The Eclipse Public License is available at 
 *   http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at 
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Developer:
 *    Alka Gupta
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "MQTTAsync.h"

#if !defined(WIN32)
#include <unistd.h>
#else
#include <windows.h>
#endif

#if defined(_WRS_KERNEL)
#include <OsWrapper.h>
#endif

#define ADDRESS     "tcp://broker.emqx.io:1883"
#define CLIENTID    "snort-mqtt-publisher"
#define TOPIC       "ALERTS"
#define QOS         1
#define TIMEOUT     10000L
#define PAYLOAD_SIZE 256

volatile MQTTAsync_token deliveredtoken;
static MQTTAsync client;

int finished = 0;
static FILE* snort_log;

int isEmpty(char *string)
{
	if (string)
	{
		if (string[0] == '\0')
			return 1;
		else
			return 0;
	}
	else
		return 1;
}

void connlost(void *context, char *cause)
{
	MQTTAsync client = (MQTTAsync)context;
	MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
	int rc;

	printf("\nConnection lost\n");
	printf("     cause: %s\n", cause);

	printf("Reconnecting\n");
	conn_opts.keepAliveInterval = 20;
	conn_opts.cleansession = 1;
	if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS)
	{
		printf("Failed to start connect, return code %d\n", rc);
 		finished = 1;
	}
}

void onDisconnect(void* context, MQTTAsync_successData* response)
{
	printf("Successful disconnection\n");
	MQTTAsync_destroy(&client);
	finished = 1;
}

void onSend(void* context, MQTTAsync_successData* response)
{
	printf("Message with token value %d delivery confirmed\n", response->token);
}

void onConnectFailure(void* context, MQTTAsync_failureData* response)
{
	printf("Connect failed, rc %d\n", response ? response->code : 0);
	init_connection();
}

void getPayload(char** payload)
{
	while (strstr(*payload, "attack detected") == NULL)
	{
		memset(*payload, 0 , PAYLOAD_SIZE);
		fgets(*payload, PAYLOAD_SIZE, snort_log);
	}
	fgets(*payload, PAYLOAD_SIZE, snort_log);
	return;
}

void send_message(void* context, MQTTAsync_successData* response)
{
	MQTTAsync client = (MQTTAsync)context;
	MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
	MQTTAsync_message pubmsg = MQTTAsync_message_initializer;
	int rc;

	opts.onSuccess = onSend;
	opts.context = client;
	pubmsg.qos = QOS;
	pubmsg.retained = 0;
	deliveredtoken = 0;

	char* payload = (char*) calloc(1, PAYLOAD_SIZE);
	getPayload(&payload);

	while(!isEmpty(payload))
	{
		printf("Sending Message %s\n", payload);
		pubmsg.payload = payload;
		pubmsg.payloadlen = (int)strlen(payload);

		if ((rc = MQTTAsync_sendMessage(client, TOPIC, &pubmsg, &opts)) != MQTTASYNC_SUCCESS)
		{
			printf("Failed to start sendMessage, return code %d\n", rc);
			exit(EXIT_FAILURE);
		}
		memset(payload, 0, PAYLOAD_SIZE);
		getPayload(&payload);
	}
	return;
}

void onConnect(void* context, MQTTAsync_successData* response)
{
	printf("Successful connection\n");
	send_message(context, response);
}

int init_connection()
{
	MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
	int rc;

	MQTTAsync_create(&client, ADDRESS, CLIENTID, MQTTCLIENT_PERSISTENCE_NONE, NULL);

	MQTTAsync_setCallbacks(client, NULL, connlost, NULL, NULL);

	conn_opts.keepAliveInterval = 20;
	conn_opts.cleansession = 1;
	conn_opts.onSuccess = onConnect;
	conn_opts.onFailure = onConnectFailure;
	conn_opts.context = client;
	if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS)
	{
		printf("Failed to start connect, return code %d\n", rc);
		exit(EXIT_FAILURE);
	}
	return rc;
}

int main(int argc, char* argv[])
{

	snort_log = fopen("./dat/alert.ids", "r");

	init_connection();

	while(1);

	return 0;
}
  
