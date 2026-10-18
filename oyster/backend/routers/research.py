"""Admin-gated research and optional fixed-scenario validation. No arbitrary target input."""
import asyncio
import dataclasses
from pathlib import Path
import config
from redbears_research.api import Runs, router_for
from redbears_research.providers import Providers
from services.investigation import workflow
from services.lab import provisioner


def providers():
    return Providers(lambda key, default='': getattr(config, key, default))


async def provision_owned(operation, *args):
    # Thread cancellation does not stop a spawned process. Wait for this owned
    # provision/reset to finish and clean its result before propagating cancellation.
    task = asyncio.create_task(asyncio.to_thread(operation, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        try:
            instance = await task
            await asyncio.to_thread(provisioner.cleanup_instance, instance.id)
        finally:
            raise


async def validate_lab(scenario_id, emit):
    if scenario_id not in ('idor_basket_access', 'sqli_login_bypass'):
        raise ValueError('Unsupported scenario')
    instance = fresh = None
    try:
        emit('lab_stage', stage='prepare_lab', detail='Checking isolation and provisioning the pinned lab.')
        instance = await provision_owned(provisioner.create_instance, scenario_id)
        result = await workflow.stage_validate(scenario_id, instance)
        emit('lab_stage', stage='validate', detail=result.detail)
        prefix = 'idor' if scenario_id.startswith('idor') else 'sqli'
        baseline = await workflow.stage_detect(scenario_id, instance, prefix + '_baseline', result.data.get('context', {}))
        emit('lab_stage', stage='detect', detail=baseline.detail)
        fresh = await provision_owned(provisioner.reset_instance, instance.id)
        rerun = await workflow.stage_validate(scenario_id, fresh)
        improved = await workflow.stage_detect(scenario_id, fresh, prefix + '_improved', rerun.data.get('context', {}))
        emit('lab_stage', stage='improve_and_verify', detail=f'{rerun.detail} {improved.detail}')
        return {'kind': 'lab_observation', 'scenario_id': scenario_id, 'simulation': result.data['simulation'],
            'detection': baseline.data['detection'], 'retest_simulation': rerun.data['simulation'],
            'retest_detection': improved.data['detection'],
            'benign_events_checked': improved.data['benign_events_checked'],
            'false_positive_on_benign': improved.data['false_positive_on_benign'],
            'lab_version': config.LAB_JUICE_SHOP_VERSION, 'lab_commit': config.LAB_JUICE_SHOP_COMMIT,
            'limitations': 'Known vulnerable benchmark; harness-supplied IDOR ownership; predefined rules; detection improvement does not fix the application.'}
    finally:
        for item in (fresh, instance):
            if item:
                await asyncio.to_thread(provisioner.cleanup_instance, item.id)


runs = Runs(Path(config.DATA_DIR) / 'research', providers, validate_lab)
router = router_for(runs)
