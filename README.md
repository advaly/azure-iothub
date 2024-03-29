## Summary

Azure IoT-Hub client.

- Listen cloud to device message
- Send device to cloud message
- Upload file
- Download file

## Example

### C2D

```
$ export SHARED_ACCESS_KEY=XXXXX
$ azure-iothub --device-id device1 --name test-iothub c2d -c ./cb.sh
```

The callback function is called with recieved message from cloud as an argument.

### D2C
Message is assumed to be a JSON format.
Add `-t` option if you want to send a text/plain message.

```
$ export SHARED_ACCESS_KEY=XXXXX
$ azure-iothub --device-id device1 --name test-iothub d2c -b '{"text": "hello world!"}'
$ azure-iothub --device-id device1 --name test-iothub d2c -t -b 'hello world!'
```

### Upload file

```
$ export SHARED_ACCESS_KEY=XXXXX
$ azure-iothub --device-id device1 --name test-iothub upload -b test.dat -f ./test.dat
```

### Download file

```
$ export SHARED_ACCESS_KEY=XXXXX
$ azure-iothub --device-id device1 --name test-iothub download -b test.dat -f ./test.dat
```

### Show SAS
```
$ export SHARED_ACCESS_KEY=XXXXX
$ azure-iothub --device-id device1 --name test-iothub sas
SharedAccessSignature sr=test-iothub.azure-devices.net%2Fdevices%2Fdevice1&sig=YYYYY
```
