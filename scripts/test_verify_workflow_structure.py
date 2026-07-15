# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

import yaml

import verify_workflow_structure as verifier


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github/workflows"


class WorkflowStructureTests(unittest.TestCase):
    def setUp(self):
        self.release = verifier.load_workflow(WORKFLOW_ROOT / "release.yml")
        self.nightly = verifier.load_workflow(WORKFLOW_ROOT / "nightly.yml")
        self.gui = verifier.load_workflow(WORKFLOW_ROOT / "gui-release.yml")
        self.ci = verifier.load_workflow(WORKFLOW_ROOT / "ci.yml")
        self.security = verifier.load_workflow(WORKFLOW_ROOT / "security.yml")

    def write_workflow(self, document, *, comment: str = "") -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", encoding="utf-8", delete=False
        )
        with temporary:
            yaml.safe_dump(document, temporary, sort_keys=False)
            if comment:
                temporary.write(comment)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return Path(temporary.name)

    def test_accepts_current_release_workflow_structure(self):
        verifier.verify_repository_workflows(REPOSITORY_ROOT)

    def test_comments_cannot_stand_in_for_missing_steps(self):
        document = copy.deepcopy(self.release)
        steps = document["jobs"]["sbom"]["steps"]
        steps[:] = [
            step
            for step in steps
            if step.get("name") != "Generate and verify dependency-backed SPDX SBOMs"
        ]
        path = self.write_workflow(
            document,
            comment=(
                "\n# - name: Generate and verify dependency-backed SPDX SBOMs\n"
                "#   run: scripts/generate_release_sboms.sh artifacts sbom\n"
            ),
        )
        with self.assertRaisesRegex(verifier.WorkflowError, "exactly one enabled step"):
            verifier.verify_release_workflow(verifier.load_workflow(path))

    def test_rejects_disabled_misplaced_or_reconditioned_steps(self):
        mutations = []

        disabled = copy.deepcopy(self.release)
        self.find_step(
            disabled, "sbom", "Generate and verify dependency-backed SPDX SBOMs"
        )["if"] = False
        mutations.append((disabled, "disabling condition"))

        misplaced = copy.deepcopy(self.release)
        package_steps = misplaced["jobs"]["package-linux"]["steps"]
        step = next(
            step for step in package_steps if step.get("name") == "Verify .deb contents"
        )
        package_steps.remove(step)
        misplaced["jobs"]["identity"]["steps"].append(step)
        mutations.append((misplaced, "exact reviewed step sequence"))

        condition = copy.deepcopy(self.release)
        self.find_step(condition, "build", "Verify Windows release archive")[
            "if"
        ] = "runner.os != 'Windows'"
        mutations.append((condition, "wrong or disabling condition"))

        disabled_job = copy.deepcopy(self.release)
        disabled_job["jobs"]["attest"]["if"] = False
        mutations.append((disabled_job, "must not have a disabling condition"))

        ignored_failure = copy.deepcopy(self.release)
        self.find_step(
            ignored_failure, "attest", "Assemble and verify attestation subjects"
        )["continue-on-error"] = True
        mutations.append((ignored_failure, "must not continue on error"))

        for index, (document, message) in enumerate(mutations):
            with self.subTest(index=index), self.assertRaisesRegex(
                verifier.WorkflowError, message
            ):
                verifier.verify_release_workflow(document)

    def test_rejects_wrong_dependencies_and_permissions(self):
        dependencies = copy.deepcopy(self.release)
        dependencies["jobs"]["attest"]["needs"].remove("gate")
        with self.assertRaisesRegex(verifier.WorkflowError, "wrong dependencies"):
            verifier.verify_release_workflow(dependencies)

        permissions = copy.deepcopy(self.release)
        permissions["jobs"]["attest"]["permissions"]["id-token"] = "read"
        with self.assertRaisesRegex(verifier.WorkflowError, "wrong permissions"):
            verifier.verify_release_workflow(permissions)

    def test_rejects_command_text_that_is_not_executed(self):
        document = copy.deepcopy(self.release)
        step = self.find_step(
            document,
            "gate",
            "Require successful CI and security runs for the release commit",
        )
        step["run"] = (
            "echo 'python3 scripts/release_tools.py verify-workflows "
            "--workflow ci.yml --workflow security.yml'"
        )
        with self.assertRaisesRegex(verifier.WorkflowError, "not exact"):
            verifier.verify_release_workflow(document)

    def test_rejects_unrecognized_jobs_in_every_reviewed_workflow(self):
        cases = [
            ("release.yml", verifier.verify_release_workflow),
            ("nightly.yml", verifier.verify_nightly_workflow),
            ("gui-release.yml", verifier.verify_gui_workflow),
            ("ci.yml", verifier.verify_ci_workflow),
            ("security.yml", verifier.verify_security_workflow),
        ]
        for workflow_name, verify in cases:
            document = verifier.load_workflow(WORKFLOW_ROOT / workflow_name)
            document["jobs"]["bypass-publish"] = {
                "runs-on": "ubuntu-latest",
                "permissions": {"contents": "write"},
                "steps": [{"run": "gh release create bypass artifact"}],
            }
            with self.subTest(workflow=workflow_name), self.assertRaisesRegex(
                verifier.WorkflowError, "wrong job set"
            ):
                verify(document)

    def test_rejects_echoed_unreachable_and_conditionally_wrapped_controls(self):
        unreachable = copy.deepcopy(self.release)
        deb = self.find_step(unreachable, "package-linux", "Verify .deb contents")
        deb["run"] = "exit 0\n" 'scripts/verify_linux_package_manifest.sh deb "$deb"\n'

        delimited_exit = copy.deepcopy(self.release)
        deb = self.find_step(delimited_exit, "package-linux", "Verify .deb contents")
        deb["run"] = (
            "echo preparing; exit 0\n"
            'scripts/verify_linux_package_manifest.sh deb "$deb"\n'
        )

        conditional = copy.deepcopy(self.release)
        deb = self.find_step(conditional, "package-linux", "Verify .deb contents")
        deb["run"] = (
            "if false; then\n"
            '  scripts/verify_linux_package_manifest.sh deb "$deb"\n'
            "fi\n"
        )

        shadowed = copy.deepcopy(self.release)
        identity = self.find_step(shadowed, "identity", "Bind tag, version, and commit")
        identity["run"] = f"python3() {{ :; }}\n{identity['run']}"

        for label, document, message in (
            ("early exit", unreachable, "successful early exit"),
            ("delimited exit", delimited_exit, "successful early exit"),
            ("conditional", conditional, "unreviewed shell control flow"),
            ("function shadow", shadowed, "not exact"),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                verifier.WorkflowError, message
            ):
                verifier.verify_release_workflow(document)

    def test_rejects_hash_and_shell_resolution_poisoning(self):
        commands = (
            "hash -p /bin/true python3",
            "X=1 hash -p /bin/true python3",
            "hash -r",
            "BASH_CMDS[python3]=/bin/true",
            "X=1 printf -v 'BASH_CMDS[python3]' /bin/true",
            "source /tmp/poison",
            ". /tmp/poison",
            "builtin hash -p /bin/true python3",
            "printf -v 'BASH_CMDS[python3]' /bin/true",
            "export LD_PRELOAD=/tmp/poison.so",
            ":; function python3 { return 0; }",
            "function python3\n{\n  :\n}",
            "X=1 eval $'function python3\\n{ :; }'",
            "X=1 shopt -s expand_aliases\nX=1 alias python3=true",
            "command_name=hash\n$command_name -p /bin/true python3",
        )
        for command in commands:
            document = copy.deepcopy(self.release)
            verification = self.find_step(
                document, "package-linux", "Verify .deb contents"
            )
            verification["run"] = f"{command}\n{verification['run']}"
            with self.subTest(command=command), self.assertRaisesRegex(
                verifier.WorkflowError,
                "command resolution|function definition|shell execution|shell state|protected|dynamically resolves",
            ):
                verifier.verify_release_workflow(document)

    def test_rejects_job_defaults_that_mask_publication_failures(self):
        cases = (
            (self.release, "gate", verifier.verify_release_workflow),
            (self.nightly, "gate", verifier.verify_nightly_workflow),
            (self.gui, "build-windows", verifier.verify_gui_workflow),
        )
        for workflow, job_name, verify in cases:
            document = copy.deepcopy(workflow)
            document["jobs"][job_name]["defaults"] = {
                "run": {"shell": "bash {0} || true"}
            }
            with self.subTest(job=job_name), self.assertRaisesRegex(
                verifier.WorkflowError, "execution defaults"
            ):
                verify(document)

    def test_rejects_extra_steps_or_runtime_changes_around_exact_controls(self):
        cases = (
            (self.release, "identity", verifier.verify_release_workflow),
            (self.release, "gate", verifier.verify_release_workflow),
            (self.nightly, "source", verifier.verify_nightly_workflow),
            (self.nightly, "gate", verifier.verify_nightly_workflow),
        )
        for workflow, job_name, verify in cases:
            document = copy.deepcopy(workflow)
            document["jobs"][job_name]["steps"].insert(
                0, {"name": "Poison command resolution", "run": "echo bypass"}
            )
            with self.subTest(job=job_name), self.assertRaisesRegex(
                verifier.WorkflowError, "exact reviewed step sequence"
            ):
                verify(document)

        runner = copy.deepcopy(self.release)
        runner["jobs"]["gate"]["runs-on"] = "self-hosted"
        with self.assertRaisesRegex(verifier.WorkflowError, "runner or timeout"):
            verifier.verify_release_workflow(runner)

    def test_rejects_commands_hidden_in_control_flow_headers(self):
        for command in (
            "eval 'python3() { return 0; }'",
            "source /tmp/poison",
            "invoke-expression /tmp/poison",
        ):
            document = copy.deepcopy(self.release)
            verification = self.find_step(
                document, "package-linux", "Verify .deb contents"
            )
            verification["run"] = f"if {command}; then\n  :\nfi\n{verification['run']}"
            with self.subTest(command=command), self.assertRaisesRegex(
                verifier.WorkflowError, "unreviewed shell control flow"
            ):
                verifier.verify_release_workflow(document)

    def test_rejects_scoped_powershell_command_provider_poisoning(self):
        release = copy.deepcopy(self.release)
        archive = self.find_step(release, "build", "Verify Windows release archive")
        archive["run"] = "function global:python { return }\n" + archive["run"]
        with self.assertRaisesRegex(verifier.WorkflowError, "not exact"):
            verifier.verify_release_workflow(release)

        for command in (
            "function global:python { return }",
            "filter global:python { return }",
            "& { function global:python { return } }",
            "$function:global:python = { return }",
            "Set-Item function:global:python { return }",
            "Microsoft.PowerShell.Management\\Set-Item function:global:python { return }",
            "Invoke-Expression 'function global:python { return }'",
            "Microsoft.PowerShell.Utility\\Invoke-Expression 'function global:python { return }'",
            "$command = 'Set-Item'\n& $command function:global:python { return }",
            "$provider = 'func' + 'tion:global:python'\nSet-Item $provider { return }",
            "& ('Set-' + 'Item') ('func' + 'tion:global:python') { return }",
        ):
            with self.subTest(command=command), self.assertRaisesRegex(
                verifier.WorkflowError,
                "protected command|command providers|command resolution|shell execution|dynamically invokes|dynamically resolves",
            ):
                verifier.powershell_script_commands(
                    {
                        "shell": "pwsh",
                        "run": f"{command}\npython scripts/verify_release_archive.py archive root",
                    },
                    "PowerShell mutation",
                )
            document = copy.deepcopy(self.gui)
            package = self.find_step(
                document, "build-windows", "Package deterministic Windows archive"
            )
            package["run"] = f"{command}\n{package['run']}"
            with self.subTest(command=command), self.assertRaises(
                verifier.WorkflowError
            ):
                verifier.verify_gui_workflow(document)

    def test_binds_executable_powershell_installer_test_command(self):
        for mutation in (
            {"run": "Write-Host skipped"},
            {"shell": "powershell"},
        ):
            document = copy.deepcopy(self.ci)
            step = self.find_step(
                document,
                "test-windows",
                "PowerShell installer bounded output tests",
            )
            step.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                verifier.WorkflowError,
                "not exact|unreviewed explicit shell topology",
            ):
                verifier.verify_ci_workflow(document)

        checksum = copy.deepcopy(self.ci)
        self.find_step(
            checksum, "test-windows", "Reject invalid Windows installer checksums"
        )["run"] = "Write-Host skipped"
        with self.assertRaisesRegex(verifier.WorkflowError, "not exact"):
            verifier.verify_ci_workflow(checksum)

    def test_exact_job_definitions_reject_every_unreviewed_field_and_step(self):
        workflows = (
            (self.release, verifier.verify_release_workflow),
            (self.nightly, verifier.verify_nightly_workflow),
            (self.gui, verifier.verify_gui_workflow),
        )
        for original, verify in workflows:
            for job_name, original_job in original["jobs"].items():
                mutations = []

                extra_step = copy.deepcopy(original)
                extra_step["jobs"][job_name].setdefault("steps", []).append(
                    {"name": "Unreviewed command", "run": "echo unreviewed"}
                )
                mutations.append(("extra step", extra_step))

                permissions = copy.deepcopy(original)
                permissions["jobs"][job_name]["permissions"] = {"contents": "write"}
                mutations.append(("permission elevation", permissions))

                defaults = copy.deepcopy(original)
                defaults["jobs"][job_name]["defaults"] = {
                    "run": {"shell": "bash {0} || true"}
                }
                mutations.append(("job defaults", defaults))

                continued = copy.deepcopy(original)
                continued["jobs"][job_name]["continue-on-error"] = True
                mutations.append(("continue on error", continued))

                run_step = next(
                    (
                        step
                        for step in original_job.get("steps", [])
                        if isinstance(step, dict) and "run" in step
                    ),
                    None,
                )
                if run_step is not None:
                    run_index = original_job["steps"].index(run_step)
                    token = copy.deepcopy(original)
                    token["jobs"][job_name]["steps"][run_index][
                        "run"
                    ] += "\necho unreviewed"
                    mutations.append(("extra token", token))

                    shell = copy.deepcopy(original)
                    shell["jobs"][job_name]["steps"][run_index][
                        "shell"
                    ] = "bash {0} || true"
                    mutations.append(("custom shell", shell))

                for mutation_name, document in mutations:
                    with self.subTest(
                        workflow=original.get("name"),
                        job=job_name,
                        mutation=mutation_name,
                    ), self.assertRaises(verifier.WorkflowError):
                        verify(document)

    def test_rejects_publication_command_added_to_existing_build_job(self):
        for original, verify, job_name in (
            (self.release, verifier.verify_release_workflow, "build"),
            (self.nightly, verifier.verify_nightly_workflow, "build"),
            (self.gui, verifier.verify_gui_workflow, "build-linux"),
        ):
            document = copy.deepcopy(original)
            job = document["jobs"][job_name]
            job["permissions"] = {"contents": "write"}
            job["steps"].append(
                {
                    "name": "Unreviewed publication",
                    "run": 'gh release create bypass --repo "$GITHUB_REPOSITORY"',
                }
            )
            with self.subTest(job=job_name), self.assertRaises(verifier.WorkflowError):
                verify(document)

    def test_publication_jobs_revalidate_workflows_immediately_before_publish(self):
        for document, job_name, publish_name in (
            (self.release, "release", "Create release from complete artifact set"),
            (self.nightly, "publish", "Publish immutable nightly release"),
        ):
            job = document["jobs"][job_name]
            self.assertEqual(
                job["permissions"], {"actions": "read", "contents": "write"}
            )
            names = [step.get("name") for step in job["steps"]]
            publish_index = names.index(publish_name)
            self.assertEqual(
                names[publish_index - 1],
                "Revalidate required workflows immediately before publication",
            )

    def test_rejects_disabled_or_rewired_ci_jobs_and_steps(self):
        for job_name in self.ci["jobs"]:
            document = copy.deepcopy(self.ci)
            document["jobs"][job_name]["if"] = False
            with self.subTest(job=job_name), self.assertRaisesRegex(
                verifier.WorkflowError, "condition"
            ):
                verifier.verify_ci_workflow(document)

        continued = copy.deepcopy(self.ci)
        continued["jobs"]["test-linux"]["continue-on-error"] = True
        with self.assertRaisesRegex(verifier.WorkflowError, "continue on error"):
            verifier.verify_ci_workflow(continued)

        step_condition = copy.deepcopy(self.ci)
        self.find_step(step_condition, "test-windows", "Unit tests")["if"] = False
        with self.assertRaisesRegex(verifier.WorkflowError, "disabling condition"):
            verifier.verify_ci_workflow(step_condition)

        rewired = copy.deepcopy(self.ci)
        rewired["jobs"]["publication-gate"]["needs"].remove("test-linux")
        with self.assertRaisesRegex(verifier.WorkflowError, "wrong dependencies"):
            verifier.verify_ci_workflow(rewired)

        matrix = copy.deepcopy(self.ci)
        matrix["jobs"]["test-linux"]["strategy"] = {"matrix": {"bypass": [True]}}
        with self.assertRaisesRegex(verifier.WorkflowError, "matrix or strategy"):
            verifier.verify_ci_workflow(matrix)

        for replacement in ("echo success", "exit 0"):
            gate = copy.deepcopy(self.ci)
            self.find_step(
                gate, "publication-gate", "Require every publication CI job to succeed"
            )["run"] = replacement
            with self.subTest(gate=replacement), self.assertRaisesRegex(
                verifier.WorkflowError, "not exact"
            ):
                verifier.verify_ci_workflow(gate)

        topology = copy.deepcopy(self.ci)
        topology["jobs"]["test-linux"]["runs-on"] = "self-hosted"
        with self.assertRaisesRegex(verifier.WorkflowError, "runner or timeout"):
            verifier.verify_ci_workflow(topology)

        custom_shell = copy.deepcopy(self.ci)
        self.find_step(custom_shell, "test-linux", "Unit & integration tests")[
            "shell"
        ] = "bash {0} || true"
        with self.assertRaisesRegex(
            verifier.WorkflowError, "unreviewed explicit shell topology"
        ):
            verifier.verify_ci_workflow(custom_shell)

    def test_rejects_disabled_rewired_or_diluted_security_jobs(self):
        mandatory = set(self.security["jobs"]) - {"dependency-review"}
        for job_name in mandatory:
            document = copy.deepcopy(self.security)
            document["jobs"][job_name]["if"] = False
            with self.subTest(job=job_name), self.assertRaisesRegex(
                verifier.WorkflowError, "condition"
            ):
                verifier.verify_security_workflow(document)

        dependency = copy.deepcopy(self.security)
        dependency["jobs"]["dependency-review"]["if"] = True
        with self.assertRaisesRegex(verifier.WorkflowError, "condition"):
            verifier.verify_security_workflow(dependency)

        matrix = copy.deepcopy(self.security)
        matrix["jobs"]["codeql"]["strategy"]["matrix"]["language"].pop()
        with self.assertRaisesRegex(verifier.WorkflowError, "matrix topology"):
            verifier.verify_security_workflow(matrix)

        rewired = copy.deepcopy(self.security)
        rewired["jobs"]["publication-gate"]["needs"].remove("python-sast")
        with self.assertRaisesRegex(verifier.WorkflowError, "wrong dependencies"):
            verifier.verify_security_workflow(rewired)

        continued = copy.deepcopy(self.security)
        self.find_step(continued, "python-sast", "Scan Python sources")[
            "continue-on-error"
        ] = True
        with self.assertRaisesRegex(verifier.WorkflowError, "continue on error"):
            verifier.verify_security_workflow(continued)

        for replacement in ("echo success", "exit 0"):
            gate = copy.deepcopy(self.security)
            self.find_step(
                gate,
                "publication-gate",
                "Require every publication security job to succeed",
            )["run"] = replacement
            with self.subTest(gate=replacement), self.assertRaisesRegex(
                verifier.WorkflowError, "not exact"
            ):
                verifier.verify_security_workflow(gate)

        topology = copy.deepcopy(self.security)
        topology["jobs"]["python-sast"]["defaults"] = {"run": {"shell": "true"}}
        with self.assertRaisesRegex(verifier.WorkflowError, "execution defaults"):
            verifier.verify_security_workflow(topology)

        workflow_defaults = copy.deepcopy(self.security)
        workflow_defaults["defaults"] = {"run": {"shell": "bash {0} || true"}}
        with self.assertRaisesRegex(verifier.WorkflowError, "execution defaults"):
            verifier.verify_security_workflow(workflow_defaults)

    def test_rejects_nightly_gate_bypass_and_echoed_clean_build(self):
        gate_bypass = copy.deepcopy(self.nightly)
        gate_bypass["jobs"]["gui"]["needs"].remove("gate")
        with self.assertRaisesRegex(verifier.WorkflowError, "wrong dependencies"):
            verifier.verify_nightly_workflow(gate_bypass)

        echoed_clean = copy.deepcopy(self.release)
        step = self.find_step(
            echoed_clean, "build", "Compare independent clean Linux core build"
        )
        step["run"] = step["run"].replace(
            'cargo clean --target "$TARGET"',
            "echo 'cargo clean --target \"$TARGET\"'",
        )
        with self.assertRaisesRegex(verifier.WorkflowError, "required command"):
            verifier.verify_release_workflow(echoed_clean)

    def test_rejects_unpinned_publication_environment(self):
        document = copy.deepcopy(self.release)
        document["env"]["MXC_REF"] = "main"
        with self.assertRaisesRegex(verifier.WorkflowError, "wrong MXC_REF"):
            verifier.verify_release_workflow(document)

    def test_rejects_duplicate_yaml_keys(self):
        path = self.write_workflow(
            {"name": "fixture", "jobs": {}}, comment="jobs: {}\n"
        )
        with self.assertRaisesRegex(verifier.WorkflowError, "duplicate YAML key"):
            verifier.load_workflow(path)

    @staticmethod
    def find_step(document, job_name, step_name):
        return next(
            step
            for step in document["jobs"][job_name]["steps"]
            if step.get("name") == step_name
        )


if __name__ == "__main__":
    unittest.main()
