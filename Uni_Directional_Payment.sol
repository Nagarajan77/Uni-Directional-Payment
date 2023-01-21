//SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.16;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.5/contracts/utils/cryptography/ECDSA.sol";

contract UNIdirection_payment_channel{

    using ECDSA for bytes32;

    address payable public sender;
    address payable public receiver;
    uint public duration = 7 days;
    uint public expiresAt;
    mapping(address => bool) public transaction_done; // to against replay attack

    constructor(address payable _receiver){
        sender = payable(msg.sender);
        receiver = _receiver;
        expiresAt = block.timestamp + duration;

    }

    function gethash(uint _amount,uint _nonce) public view returns(bytes32){  // nonce, contract address used to against replay attack
        return keccak256(abi.encodePacked(address(this),_amount,_nonce));
    }

    function ethsign_gethash(uint _amount,uint _nonce) public view returns(bytes32){
        return gethash(_amount,_nonce).toEthSignedMessageHash();
    }

    function verify_sig(uint _amount, uint _nonce, bytes memory _sig) public view returns(address){
        return ethsign_gethash(_amount,_nonce).recover(_sig);
    }

    function transact(uint _amount,uint _nonce,bytes memory _sig) external {
        require(msg.sender == receiver,"wrong address calling");
        require(block.timestamp <= expiresAt,"contract time expired");

        address _receiver = verify_sig(_amount,_nonce,_sig);
        require(msg.sender == _receiver,"wrong address/wrong signature");
        require(!transaction_done[_receiver],"already tx claimed");

        (bool sent,) = receiver.call{value : _amount}("");
        require(sent,"transaction, failed");
        transaction_done[_receiver] = true;

        selfdestruct(sender);
    }

    function expire_contract() external {
        require(msg.sender == sender);
        require(block.timestamp > expiresAt,"contract channel is still live");
        require(!transaction_done[receiver],"already tx claimed");

        selfdestruct(sender);

    }
}
