// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MessageContract {
    // Event to emit when a message hash is logged
    event MessageLogged(bytes32 messageHash);

    // Function to log the message hash
    function logMessage(bytes32 messageHash) public {
        emit MessageLogged(messageHash);
    }
}
