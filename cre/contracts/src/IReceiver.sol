// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC165} from "./IERC165.sol";

/// @notice Chainlink CRE consumer callback. The KeystoneForwarder calls this
/// after it has checked the workflow's signatures.
interface IReceiver is IERC165 {
    function onReport(bytes calldata metadata, bytes calldata report) external;
}
