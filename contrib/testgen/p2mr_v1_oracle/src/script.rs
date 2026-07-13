const MAX_STACK_ITEMS: usize = 1000;
const MAX_STACK_ITEM_BYTES: usize = 16 * 1024;
const MAX_TOTAL_STACK_BYTES: usize = 128 * 1024;

fn truthy(value: &[u8]) -> bool {
    value
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte != 0 && !(index == value.len() - 1 && *byte == 0x80))
}

fn toggle_else(conditionals: &mut [bool]) -> Result<(), &'static str> {
    let current = conditionals
        .last_mut()
        .ok_or("SCRIPT_ERR_UNBALANCED_CONDITIONAL")?;
    *current = !*current;
    Ok(())
}

fn parse_script_num(value: &[u8]) -> Result<i64, String> {
    if value.len() > 4 {
        return Err("SCRIPT_ERR_UNKNOWN_ERROR".to_string());
    }
    if let Some(last) = value.last() {
        if last & 0x7f == 0 && (value.len() == 1 || value[value.len() - 2] & 0x80 == 0) {
            return Err("SCRIPT_ERR_UNKNOWN_ERROR".to_string());
        }
    }
    let mut magnitude = 0u64;
    for (index, byte) in value.iter().enumerate() {
        magnitude |= u64::from(*byte) << (8 * index);
    }
    if value.last().is_some_and(|byte| byte & 0x80 != 0) {
        magnitude &= !(0x80u64 << (8 * (value.len() - 1)));
        Ok(-(magnitude as i64))
    } else {
        Ok(magnitude as i64)
    }
}

fn serialize_script_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let negative = value < 0;
    let mut magnitude = if negative {
        (-value) as u64
    } else {
        value as u64
    };
    let mut encoded = Vec::new();
    while magnitude != 0 {
        encoded.push((magnitude & 0xff) as u8);
        magnitude >>= 8;
    }
    if encoded.last().unwrap() & 0x80 != 0 {
        encoded.push(if negative { 0x80 } else { 0 });
    } else if negative {
        *encoded.last_mut().unwrap() |= 0x80;
    }
    encoded
}

pub fn evaluate<T, D>(
    script: &[u8],
    initial_stack: &[Vec<u8>],
    mut check_signature: T,
    mut check_data_signature: D,
) -> Result<(), String>
where
    T: FnMut(&[u8], &[u8], u32) -> Result<bool, String>,
    D: FnMut(&[u8], &[u8], &[u8]) -> Result<bool, String>,
{
    if initial_stack.len() > MAX_STACK_ITEMS {
        return Err("SCRIPT_ERR_STACK_SIZE".to_string());
    }
    if initial_stack
        .iter()
        .any(|item| item.len() > MAX_STACK_ITEM_BYTES)
        || initial_stack
            .iter()
            .try_fold(0usize, |total, item| total.checked_add(item.len()))
            .unwrap_or(usize::MAX)
            > MAX_TOTAL_STACK_BYTES
    {
        return Err("SCRIPT_ERR_PUSH_SIZE".to_string());
    }
    let mut stack = initial_stack.to_vec();
    let mut conditionals: Vec<bool> = Vec::new();
    let mut position = 0usize;
    let mut opcode_position = 0u32;
    let mut last_codesep = u32::MAX;
    while position < script.len() {
        let opcode = script[position];
        position += 1;
        let executing = conditionals.iter().all(|condition| *condition);
        match opcode {
            0x00 => {
                if executing {
                    stack.push(Vec::new());
                }
            }
            0x01..=0x4b => {
                let size = opcode as usize;
                let end = position.checked_add(size).ok_or("SCRIPT_ERR_BAD_OPCODE")?;
                if end > script.len() {
                    return Err("SCRIPT_ERR_BAD_OPCODE".to_string());
                }
                if executing {
                    stack.push(script[position..end].to_vec());
                }
                position = end;
            }
            0x51..=0x60 => {
                if executing {
                    stack.push(serialize_script_num(i64::from(opcode - 0x50)));
                }
            }
            0x61 => {}
            0x63 => {
                let parent_executes = conditionals.iter().all(|condition| *condition);
                if parent_executes {
                    let value = stack.pop().ok_or("SCRIPT_ERR_UNBALANCED_CONDITIONAL")?;
                    if !value.is_empty() && value.as_slice() != [1u8] {
                        return Err("SCRIPT_ERR_TAPSCRIPT_MINIMALIF".to_string());
                    }
                    conditionals.push(truthy(&value));
                } else {
                    conditionals.push(false);
                }
            }
            0x67 => {
                toggle_else(&mut conditionals)?;
            }
            0x68 => {
                if conditionals.pop().is_none() {
                    return Err("SCRIPT_ERR_UNBALANCED_CONDITIONAL".to_string());
                }
            }
            0x7c => {
                if executing {
                    if stack.len() < 2 {
                        return Err("SCRIPT_ERR_INVALID_STACK_OPERATION".to_string());
                    }
                    let top = stack.len() - 1;
                    stack.swap(top, top - 1);
                }
            }
            0xab => {
                if executing {
                    last_codesep = opcode_position;
                }
            }
            0xb3 => {
                if executing {
                    let pubkey = stack.pop().ok_or("SCRIPT_ERR_INVALID_STACK_OPERATION")?;
                    let signature = stack.pop().ok_or("SCRIPT_ERR_INVALID_STACK_OPERATION")?;
                    let valid = check_signature(&signature, &pubkey, last_codesep)?;
                    stack.push(if valid { vec![1] } else { Vec::new() });
                }
            }
            0xba => {
                if executing {
                    if stack.len() < 3 {
                        return Err("SCRIPT_ERR_INVALID_STACK_OPERATION".to_string());
                    }
                    let pubkey = stack.pop().unwrap();
                    let number = parse_script_num(&stack.pop().unwrap())?;
                    let signature = stack.pop().unwrap();
                    let valid = check_signature(&signature, &pubkey, last_codesep)?;
                    stack.push(serialize_script_num(number + i64::from(valid)));
                }
            }
            0xbc => {
                if executing {
                    if stack.len() < 3 {
                        return Err("SCRIPT_ERR_INVALID_STACK_OPERATION".to_string());
                    }
                    let pubkey = stack.pop().unwrap();
                    let message_hash = stack.pop().unwrap();
                    let signature = stack.pop().unwrap();
                    let valid = check_data_signature(&signature, &message_hash, &pubkey)?;
                    stack.push(if valid { vec![1] } else { Vec::new() });
                }
            }
            0xbd => {
                if executing {
                    if stack.len() < 4 {
                        return Err("SCRIPT_ERR_INVALID_STACK_OPERATION".to_string());
                    }
                    let pubkey = stack.pop().unwrap();
                    let number = parse_script_num(&stack.pop().unwrap())?;
                    let message_hash = stack.pop().unwrap();
                    let signature = stack.pop().unwrap();
                    let valid = check_data_signature(&signature, &message_hash, &pubkey)?;
                    stack.push(serialize_script_num(number + i64::from(valid)));
                }
            }
            0x9c => {
                if executing {
                    if stack.len() < 2 {
                        return Err("SCRIPT_ERR_INVALID_STACK_OPERATION".to_string());
                    }
                    let right = parse_script_num(&stack.pop().unwrap())?;
                    let left = parse_script_num(&stack.pop().unwrap())?;
                    stack.push(if left == right { vec![1] } else { Vec::new() });
                }
            }
            _ => return Err(format!("UNSUPPORTED_P2MR_OPCODE_{opcode:02x}")),
        }
        opcode_position = opcode_position
            .checked_add(1)
            .ok_or("script opcode position overflow")?;
        if stack.len() > MAX_STACK_ITEMS {
            return Err("SCRIPT_ERR_STACK_SIZE".to_string());
        }
    }
    if !conditionals.is_empty() {
        return Err("SCRIPT_ERR_UNBALANCED_CONDITIONAL".to_string());
    }
    if stack.len() != 1 {
        return Err("SCRIPT_ERR_CLEANSTACK".to_string());
    }
    if !truthy(&stack[0]) {
        return Err("SCRIPT_ERR_EVAL_FALSE".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_true_and_false() {
        assert!(evaluate(
            &[0x51],
            &[],
            |_, _, _| unreachable!(),
            |_, _, _| { unreachable!() }
        )
        .is_ok());
        assert_eq!(
            evaluate(
                &[0x00],
                &[],
                |_, _, _| unreachable!(),
                |_, _, _| unreachable!()
            )
            .unwrap_err(),
            "SCRIPT_ERR_EVAL_FALSE"
        );
    }

    #[test]
    fn rejects_unsupported_opcode() {
        assert!(evaluate(
            &[0x6a],
            &[],
            |_, _, _| unreachable!(),
            |_, _, _| unreachable!()
        )
        .unwrap_err()
        .starts_with("UNSUPPORTED_P2MR_OPCODE"));
    }

    #[test]
    fn executes_checksigadd_and_numequal() {
        let script = [0x00, 0x01, 0x02, 0xba, 0x51, 0x9c];
        assert!(evaluate(
            &script,
            &[vec![3]],
            |signature, pubkey, codesep| {
                assert_eq!(signature, [3]);
                assert_eq!(pubkey, [2]);
                assert_eq!(codesep, u32::MAX);
                Ok(true)
            },
            |_, _, _| unreachable!()
        )
        .is_ok());
    }

    #[test]
    fn executes_checkdatasig_and_checkdatasigadd() {
        let checksig_script = [0x01, 0x02, 0x01, 0x03, 0xbc];
        assert!(evaluate(
            &checksig_script,
            &[vec![1]],
            |_, _, _| unreachable!(),
            |signature, message_hash, pubkey| {
                assert_eq!(signature, [1]);
                assert_eq!(message_hash, [2]);
                assert_eq!(pubkey, [3]);
                Ok(true)
            }
        )
        .is_ok());

        let add_script = [0x01, 0x02, 0x00, 0x01, 0x03, 0xbd, 0x51, 0x9c];
        assert!(evaluate(
            &add_script,
            &[vec![1]],
            |_, _, _| unreachable!(),
            |_, _, _| Ok(true)
        )
        .is_ok());
    }

    #[test]
    fn script_numbers_roundtrip_boundaries() {
        for value in [
            -2_147_483_647,
            -129,
            -128,
            -1,
            0,
            1,
            127,
            128,
            2_147_483_647,
        ] {
            assert_eq!(
                parse_script_num(&serialize_script_num(value)).unwrap(),
                value
            );
        }
        assert_eq!(
            parse_script_num(&[0x80]).unwrap_err(),
            "SCRIPT_ERR_UNKNOWN_ERROR"
        );
        assert_eq!(
            parse_script_num(&[0; 5]).unwrap_err(),
            "SCRIPT_ERR_UNKNOWN_ERROR"
        );
    }

    #[test]
    fn distinguishes_initial_stack_count_and_byte_limits() {
        assert_eq!(
            evaluate(
                &[0x51],
                &vec![Vec::new(); MAX_STACK_ITEMS + 1],
                |_, _, _| unreachable!(),
                |_, _, _| unreachable!()
            )
            .unwrap_err(),
            "SCRIPT_ERR_STACK_SIZE"
        );
        assert_eq!(
            evaluate(
                &[0x51],
                &[vec![0; MAX_STACK_ITEM_BYTES + 1]],
                |_, _, _| unreachable!(),
                |_, _, _| unreachable!()
            )
            .unwrap_err(),
            "SCRIPT_ERR_PUSH_SIZE"
        );
    }

    #[test]
    fn empty_signature_is_a_false_check() {
        let mut script = vec![32];
        script.extend_from_slice(&[1; 32]);
        script.push(0xb3);
        assert_eq!(
            evaluate(
                &script,
                &[Vec::new()],
                |signature, pubkey, _| {
                    assert!(signature.is_empty());
                    assert_eq!(pubkey, &[1; 32]);
                    Ok(false)
                },
                |_, _, _| unreachable!()
            )
            .unwrap_err(),
            "SCRIPT_ERR_EVAL_FALSE"
        );
    }

    #[test]
    fn else_toggles_under_a_false_parent() {
        let mut conditionals = vec![false, false];
        toggle_else(&mut conditionals).unwrap();
        assert_eq!(conditionals, [false, true]);
    }
}
